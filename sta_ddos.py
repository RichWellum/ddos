#!/usr/bin/env python3
"""SecureX Traffic Analytics tool to dynamically measure the rate of change of
protocols and application and warn or alert as needed, based on user
configuration.

Requires a yaml configuration file, see README and example config.yaml

Basic premise:

This tool will continually query an SMC for flows of a particular protocol and
application profile configured by the user, over the time period now - five
minutes.

The flows are aggregated by byte count and stored in a Pandas Series. Each new
total is compared to the one below. If a percentage change above the configured
threshold value is detected, then the tool enters the alerting protocol.

The alerting protocol:

There are three levels of alerting:

1. Green - all is good, nothing to report
2. Yellow - a threshold breach has been detected
3. Red - an Alert warning has been breached.

When the threshold is first breached, then we enter the Yellow Warning level.
The Baseline Threshold Value is stored.

To get out of this level, we will have to detect 5 successive lower total byte
counts than the baseline Threshold value. If that occurs we go back to Green
level and the Baseline Threshold will start again.

However if in Yellow Warning level we get 5 successive higher than the baseline
readings then we enter: Red Alert status. There will be stay until we get 5
readings below the baseline threshold level.
"""
import argparse
import datetime
import json
import os
import pathlib
import sys
import time
from argparse import RawDescriptionHelpFormatter

import pandas as pd
import requests
import terminal_banner
import urllib3
import yaml
from termcolor import cprint

urllib3.disable_warnings()


def print_banner(description, color, attributes=None):
    """Display a bannerized print."""
    print()
    cprint(terminal_banner.Banner(description), color, "on_grey", attrs=attributes)


def parse_args():
    """Parse sys.argv and return args."""
    parser = argparse.ArgumentParser(
        formatter_class=RawDescriptionHelpFormatter,
        description="SecureX Threat Analytics - DDOS warning system",
        epilog="E.g.: ./sta_ddos.py config.yaml -v",
    )
    parser.add_argument(
        "config", help="YAML Config file see config.yaml for example",
    )
    parser.add_argument(
        "-l", "--log_output", type=str, default="Local", help="Optional log location, like '/tmp'",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="over-ride verbosity",
    )
    return parser.parse_args()


class StaDdos:
    """
    Base class for executing DevNet queries on a Stealthwatch SMC.
    """

    pd.options.display.max_rows = None
    pd.options.display.max_columns = None
    pd.options.display.width = None

    def __init__(self, args):
        """Initialize all variables."""
        self.username = ""
        self.password = ""
        self.config = args.config
        self.verbose = args.verbose

        # Alert level indicators
        # green = all good
        # yellow = warning mode, threshold was met
        # red - alert mode, warning mode was active for a long time
        self.alert_level = "green"
        self.threshold_baseline_bytes = 0
        self.alert_number = 4

        # Create a log file
        if args.log_output == "Local":
            path = pathlib.Path().absolute()
        else:
            path = args.log_output

        log_dt = datetime.datetime.utcnow()
        log_dt = log_dt.strftime("%Y-%m-%d-%H-%M-%S")
        self.warn_log_file = f"{path}/ddos_warns.{log_dt}.log"
        self.alert_log_file = f"{path}/ddos_alerts.{log_dt}.log"

        # Clear the terminal
        _ = os.system("clear")

        # Get the config
        self.get_config()

        # Run all the queries
        self.run_queries()

    def run_queries(self):
        """Runner to execute all the queries enabled in the config."""

        # DOS attack
        if self.config["dos_attack"]["enabled"]:
            self.dos_attack_vector()
            sys.exit()
        else:
            cprint("Nothing configured", "magenta")

    def get_config(self):
        """Open and read config file.

        Config file can be in yaml or json format.
        """

        # If yaml config convert to json
        if "yaml" in self.config:
            with open(self.config, "r") as stream:
                try:
                    self.config = yaml.safe_load(stream)
                except yaml.YAMLError as exc:
                    print(exc)
        else:
            # JSON config file
            try:
                with open(self.config, "r") as file:
                    self.config = json.load(file)
            except FileNotFoundError:
                sys.exit(f"Configuration file '{self.config}' not found")

        if not self.verbose:
            self.verbose = self.config["dos_attack"]["verbose"]

        # Set DDOS values
        self.dos_flow_time = self.config["dos_attack"]["dos_flow_time"]
        self.dos_flow_repeat_time = self.config["dos_attack"]["dos_flow_repeat_time"]
        self.dos_threshold = self.config["dos_attack"]["dos_threshold"]
        # self.dos_spike = self.config["dos_attack"]["dos_spike"]
        self.protocol = self.config["dos_attack"]["protocol"]
        self.applications = self.config["dos_attack"]["applications"]

        # Set global config values from config file
        self.username = self.config["SMC"]["username"]
        self.password = self.config["SMC"]["password"]
        self.host = self.config["SMC"]["host"]
        self.tenant = self.config["SMC"]["tenant"]

    def dos_attack_vector(self):
        """Sequence a dDOS attack vector.

        Query 5 minutes of Active protocol traffic.

        Check against various Thresholds and Alerts and inform the user.

        Requires a config.yaml file - see example.
        """
        # spike_alert = False

        banner = (
            f"DDOS ATTACK VECTOR\n"
            f"Host: {self.host}\n"
            f"Tenant: {self.tenant}\n"
            f"Flow time queried: {self.dos_flow_time}s\n"
            f"Repeat every: {self.dos_flow_repeat_time}s\n"
            f"Percentage Warning Threshold: {self.dos_threshold}%\n"
            f"Alert Threshold: Protocol IDs: {self.protocol}\n"
            f"Application IDs: {self.applications}"
            # f"Warn  Log file: {self.warn_log_file}\n"
            # f"Alert Log file: {self.alert_log_file}"
        )

        # with open(self.warn_log_file, "a") as file:
        #     file.write(
        #         f"\n{datetime.datetime.utcnow()} - Warning: Percentage Change: "
        #         f"{new_byte_perc}% >= {self.dos_threshold}% threshold"
        #     )
        #     file.close()

        #     with open(self.alert_log_file, "a") as file:
        #         file.write(
        #             f"\n{datetime.datetime.utcnow()} - Alert: Byte count percentage spiked >= {self.dos_spike} times over {self.dos_threshold}%"
        #         )
        #         file.close()

        print_banner(
            banner, "white", ["bold"],
        )

        with open(self.warn_log_file, "a") as file:
            file.write("**-DDOS WARNINGS-**\n")
            file.write(f"{banner}\n")

        with open(self.alert_log_file, "a") as file:
            file.write("**-DDOS ALERTS-**\n")
            file.write(f"{banner}\n")

        # Setup Pandas Series
        data_totals = pd.DataFrame(columns=["id"])
        data_totals_t = pd.DataFrame(columns=["AllBytes"])
        perc_change_df = pd.DataFrame(columns=["Byte_change"])

        while True:
            # Login and create a session
            # Set the URL for SMC login
            url = f"https://{self.host}/token/v2/authenticate"

            # Create the login request data
            login_request_data = {"username": self.username, "password": self.password}

            # Initialize the Requests session
            api_session = requests.Session()

            # Perform the POST request to login
            res = api_session.request("POST", url, verify=False, data=login_request_data)

            # If the login was successful
            if res.status_code != 200:
                cprint("Login unsuccessful", "red")
                sys.exit(1)

            # Set the URL for the query to POST the filter and initiate the search
            url = f"https://{self.host}/sw-reporting/v2/tenants/{self.tenant}/flows/queries"

            # Populate the window to check flows.
            end_datetime = datetime.datetime.utcnow()
            start_datetime = end_datetime - datetime.timedelta(seconds=self.dos_flow_time)
            end_datetime = end_datetime.strftime("%Y-%m-%dT%H:%M:%SZ")
            start_datetime = start_datetime.strftime("%Y-%m-%dT%H:%M:%SZ")

            # Populate the payload to make the protocol query
            payload = {
                "startDateTime": start_datetime,
                "endDateTime": end_datetime,
                "subject": {"orientation": "Either"},
                "flow": {
                    "flowDirection": "BIDIRECTIONAL",
                    "applications": self.applications,
                    "protocol": self.protocol,
                    "includeInterfaceData": "true",
                },
            }
            cprint(
                f"\n{self.dos_flow_time}s probe -- protocol({self.protocol}), "
                f"applications({self.applications}) flow request to: {self.host}",
                self.alert_level,
            )
            if self.verbose:
                cprint(
                    f"\nSMC Query Payload: {json.dumps(payload, indent=2)}",
                    "red",
                    "on_grey",
                    attrs=["bold"],
                )

            # Perform the query to initiate the search
            request_headers = {"Content-type": "application/json", "Accept": "application/json"}
            try:
                res = api_session.request(
                    "POST", url, verify=False, data=json.dumps(payload), headers=request_headers
                )
            except Exception as exc:
                cprint("Generated an exception: %s" % exc, "red")
                time.sleep(self.dos_flow_repeat_time)
                continue
                # raise exc
            else:
                if not res.ok:
                    cprint(f"Server issue: {res.status_code}", "magenta")
                    time.sleep(self.dos_flow_repeat_time)
                    continue

                if res.status_code != 201:
                    cprint(
                        f"An error has ocurred, while getting flows, with the following code {res.status_code}",
                        "red",
                    )
                    url = f"https://{self.host}/token"
                    res = api_session.delete(url, timeout=30, verify=False)
                    time.sleep(self.dos_flow_repeat_time)
                    continue

                search = json.loads(res.content)["data"]["query"]

                # Set the URL to check the search status
                url = f"https://{self.host}/sw-reporting/v2/tenants/{self.tenant}/flows/queries/{search['id']}"

                # While search status is not complete, check the status every
                # 5s
                failures = 0
                while search["percentComplete"] != 100.0:
                    time.sleep(5)
                    try:
                        res = api_session.request("GET", url, verify=False)
                        search = res.json()["data"]["query"]
                        failures = 0
                    except (json.decoder.JSONDecodeError, requests.RequestException):
                        failures += 1
                    if failures >= 9:
                        if self.verbose:
                            res.raise_for_status()
                        else:
                            sys.exit(
                                f"Query failed to complete after #{failures} retries - exiting"
                            )

                # Set the URL to check the search results and get them
                url = f"https://{self.host}/sw-reporting/v2/tenants/{self.tenant}/flows/queries/{search['id']}/results"
                res = api_session.request("GET", url, verify=False)
                results = json.loads(res.content)["data"]

                new_data_active = pd.json_normalize(results, record_path="flows")
                if new_data_active.empty:
                    cprint("No new data", "magenta")
                    time.sleep(self.dos_flow_repeat_time)
                    print()
                    continue

                # Filter out some fields
                new_data_active = new_data_active[
                    [
                        "id",
                        "peer.bytes",
                        "subject.bytes",
                        "peer.packets",
                        "subject.packets",
                        "statistics.lastActiveTime",
                    ]
                ]

                # Create new dataframe with total sum of all bytes
                data_totals["id"] = new_data_active["id"]
                data_totals["TotalBytes"] = (
                    new_data_active["peer.bytes"].sum() + new_data_active["subject.bytes"].sum()
                )

                # Another new data frame to just contain all bytes summed up
                # into one row
                last_total_sum = int([data_totals["TotalBytes"].sum()])
                data_totals_t.loc[len(data_totals_t)] = last_total_sum

                if self.verbose:
                    cprint(f"Total Protocol Bytes\n{data_totals_t}", self.alert_level)
                    print()

                # Check to see if we breach our threshold
                if self.alert_level == "green":
                    # Calculate the percentage change between the latest and the
                    # last entry
                    perc_change_df = data_totals_t.pct_change() * 100
                    perc_change_df.columns = [
                        "Byte_change",
                    ]
                    perc_change_df = perc_change_df.round(2)
                    perc_change_df["Byte_change"] = perc_change_df["Byte_change"].fillna(0)
                    new_byte_perc = perc_change_df.tail(1)["Byte_change"]
                    new_byte_perc = new_byte_perc.iloc[0]

                    if new_byte_perc >= self.dos_threshold:
                        self.alert_level = "yellow"
                        self.threshold_baseline_bytes = last_total_sum
                        self.alert_number = 4
                        print_banner(
                            f"Status Yellow: Protocol Byte percentage change: {new_byte_perc}% >= "
                            f"Protocol Byte percentage threshold: {self.dos_threshold}%\n"
                            f"Threshold baseline bytes: {last_total_sum}\n"
                            f"Warning level set to: {self.alert_level}",
                            self.alert_level,
                        )
                    else:
                        cprint(
                            f"Status Green: Protocol Byte percentage change: {new_byte_perc}% < Byte percentage threshold "
                            f"{self.dos_threshold}%",
                            self.alert_level,
                        )

                elif self.alert_level == "yellow":
                    # ignore percentage change - look for 5 repeats below the
                    # threshold_baseline_bytes
                    if last_total_sum < self.threshold_baseline_bytes:
                        self.alert_number -= 1
                    elif last_total_sum > self.threshold_baseline_bytes:
                        self.alert_number += 1
                    if self.alert_number == 0:
                        # todo: make this a dict
                        self.alert_level = "green"
                        self.alert_number = 4
                        print_banner(
                            f"Threshold Warning over, last total byte count: {last_total_sum}, threshold baseline bytes reset",
                            self.alert_level,
                        )
                    elif self.alert_number == 9:
                        self.alert_level = "red"
                        print_banner(
                            "Status Red: 5 consecutive increases beyond warning level, moving to red...",
                            self.alert_level,
                        )
                    else:
                        cprint(
                            f"Status unchanged: Last total {last_total_sum}, "
                            f"threshold baseline bytes {self.threshold_baseline_bytes}, "
                            f"Warning level: {self.alert_number}",
                            self.alert_level,
                        )

                elif self.alert_level == "red":
                    # We're in highest category of alert - can we move to yellow?
                    if last_total_sum < self.threshold_baseline_bytes:
                        self.alert_number -= 1
                    elif last_total_sum >= self.threshold_baseline_bytes:
                        self.alert_number += 1
                        self.alert_number = min(self.alert_number, 10)

                    if self.alert_number >= 4:
                        # Red alert over - reset to yellow (todo: make this a
                        # dict)
                        self.alert_level = "yellow"
                        print_banner(
                            f"Threshold Alert over, Last total {last_total_sum}, "
                            f"threshold baseline bytes {self.threshold_baseline_bytes}, moving to yellow...",
                            self.alert_level,
                        )
                    else:
                        cprint(
                            f"Status unchanged: Last total {last_total_sum}, "
                            f"threshold baseline bytes {self.threshold_baseline_bytes}, Alert number {self.alert_number}",
                            self.alert_level,
                        )

                time.sleep(self.dos_flow_repeat_time)


def main():
    """Code to query a SMC."""
    args = parse_args()

    try:
        StaDdos(args)

    except Exception:
        print("Exception caught:")
        print(sys.exc_info())
        raise


if __name__ == "__main__":
    main()
