#!/usr/bin/env python3
"""SecureX Traffic Analytics tool to dynamically measure the rate of change of
protocols and application and warn or alert as needed, based on user
configuration.

Requires a yaml configuration file, see README and example config.yaml
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
        self.dos_spike = self.config["dos_attack"]["dos_spike"]
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
        spike_alert = False

        banner = (
            f"DDOS ATTACK VECTOR\nHost: {self.host}\nTenant: {self.tenant}\n"
            f"Flow time queried: {self.dos_flow_time}s\nRepeat every: {self.dos_flow_repeat_time}s\n"
            f"Percentage Warning Threshold: {self.dos_threshold}%\n"
            f"Alert Threshold: {self.dos_spike} warnings\nProtocol IDs: {self.protocol}\nApplication IDs: {self.applications}\n"
            f"Warn  Log file: {self.warn_log_file}\n"
            f"Alert Log file: {self.alert_log_file}"
        )

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
                f"\n{self.dos_flow_time}s -- protocol({self.protocol}), applications({self.applications}) flow request to: {self.host}",
                "magenta",
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
                            sys.exit("Query failed to complete - exiting")

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

                #
                # I believe there is no need to remove non active flows because
                # by definition the API only returns active flows in a time
                # period. Also no need to aggregate per flow id - as the SMC
                # has done this already.
                #

                # Create new dataframe with total sum of all bytes
                data_totals["id"] = new_data_active["id"]
                data_totals["TotalBytes"] = (
                    new_data_active["peer.bytes"].sum() + new_data_active["subject.bytes"].sum()
                )

                # Another new data frame to just contain all bytes summed up into one row
                data_totals_t.loc[len(data_totals_t)] = [data_totals["TotalBytes"].sum()]

                if self.verbose:
                    cprint(f"Total Protocol Bytes\n{data_totals_t}", "green")
                    print()

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

                # Check to see if we breach our threshold
                if new_byte_perc >= self.dos_threshold:
                    cprint(
                        f"  Warning: Percentage Change: {new_byte_perc}% >= {self.dos_threshold}% threshold, Gather {self.dos_flow_repeat_time}s more data...",
                        "cyan",
                        attrs=["bold", "blink"],
                    )
                    with open(self.warn_log_file, "a") as file:
                        file.write(
                            f"\n{datetime.datetime.utcnow()} - Warning: Percentage Change: {new_byte_perc}% >= {self.dos_threshold}% threshold"
                        )
                        file.close()
                else:
                    cprint(
                        f"  Info: Percentage Change: {new_byte_perc}% < {self.dos_threshold}% threshold, Gather {self.dos_flow_repeat_time}s more data...",
                        "green",
                        attrs=["bold"],
                    )
                    if self.verbose:
                        cprint("No Warning", "green")

                # Check to see if we need to alert
                # Only look at the last X attempts
                perc_change_df = perc_change_df.tail(5)
                perc_change_df.reset_index(drop=True, inplace=True)
                byte_spike = 0

                # Count number of times percentage spiked
                for _, row in perc_change_df.iterrows():
                    if row["Byte_change"] > self.dos_threshold:
                        byte_spike += 1
                    else:
                        # If in alert status stay unless the percentage change
                        # has dropped, in which case reduce the spike count
                        if spike_alert:
                            byte_spike -= 1

                spike_alert = bool(byte_spike >= self.dos_spike)
                if spike_alert:
                    cprint(perc_change_df, "red")
                    cprint(
                        f"Alert!: Byte count percentage spiked >= {self.dos_spike} times over {self.dos_threshold}%",
                        "red",
                        attrs=["bold", "blink"],
                    )
                    with open(self.alert_log_file, "a") as file:
                        file.write(
                            f"\n{datetime.datetime.utcnow()} - Alert: Byte count percentage spiked >= {self.dos_spike} times over {self.dos_threshold}%"
                        )
                        file.close()
                else:
                    if self.verbose:
                        cprint(perc_change_df, "green")
                        cprint("No Alert", "green")

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
