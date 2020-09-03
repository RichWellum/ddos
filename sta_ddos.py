#!/usr/bin/env python3
"""SecureX Traffic Analytics tool to dynamically measure the rate of change of
protocols and application and warn or alert as needed, based on user
configuration.

Requires a yaml configuration file, see README and example config.yaml

Basic premise:

This is a two step tool.

Step1. Run the tool with a --inspect switch.

In this mode the tool will continuously query for the total byte count of a
particular protocol profile, and creating a mean value seen. This mean value is
then used in Step 2 to determine potential maliscious rates of change. The user
can run this as long as needed, the longer the better is the assumption.

Step 2. Run the tool without --inspect mode

This tool will continually query an SMC for flows of a particular protocol and
application profile configured by the user, over the time period now - five
minutes.

The baseline is set by the config param ``dos_baseline``. Populate this with
the results of running this profile in '--inspect' mode. If set to '0' - then
sta_ddos will attempt to form a dynamic baseline from the previous 5 queries.
This may result in less accurate alerts..

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

todo:

1. De-complicate main fn and modularize
2. Handle multiple profiles
"""
import argparse
import datetime
import json
import os
import signal
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


def size(bytes_number):
    """Convert bytes into something readable."""
    tags = ["Bytes", "Kilobytes", "Megabytes", "Gigabytes", "Terabytes"]

    tag_cnt = 0
    double_bytes = bytes_number

    while tag_cnt < len(tags) and bytes_number >= 1024:
        double_bytes = bytes_number / 1024.0
        tag_cnt += 1
        bytes_number = bytes_number / 1024

    return str(round(double_bytes, 2)) + " " + tags[tag_cnt]


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
    # parser.add_argument(
    #     "-l", "--log_output", type=str, default="Local", help="Optional log location, like '/tmp'",
    # )
    parser.add_argument(
        "-i",
        "--inspect",
        action="store_true",
        help="inspect mode will watch a protocol profile and help form a baseline value",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="over-ride verbosity",
    )
    return parser.parse_args()


def status_change(new, baseline):
    """Report on a status change."""
    if new > baseline:
        status = f"Byte count: {size(new)} is higher than baseline: {size(baseline)}"
    elif new < baseline:
        status = f"Byte count: {size(new)} lower than baseline: {size(baseline)}"
    else:
        status = "Byte count unchanged"
    return status


def get_percent_change(current, baseline):
    """Get percentage change between new byte count and baseline."""
    if current == baseline:
        return 0
    try:
        return ((current - baseline) / baseline) * 100.0
    except ZeroDivisionError:
        return float("inf")


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
        self.inspect = args.inspect

        # Alert level indicators
        # green = all good (0)
        # yellow = warning mode, threshold was met (5-9)
        # red - alert mode, warning mode was active for a long time (10)
        self.alert_color = "green"
        self.alert_level = 0
        self.inspect_ave_bc = 0
        self.dos_baseline = 0

        log_dt = datetime.datetime.utcnow()
        log_dt = log_dt.strftime("%Y-%m-%d-%H-%M-%S")

        # Clear the terminal
        _ = os.system("clear")

        # Catch CTRC-C
        signal.signal(signal.SIGINT, self.signal_handler)

        # Get the config
        self.get_config()

        # Run all the queries
        self.run_queries()

    def get_app_details(self):
        """Load Stealthwatch Application IDs and return details"""
        # Load system application definitions
        app_dict = []
        app_name_dict = []
        with open("system_application_definitions.json") as json_data:
            data = json.load(json_data)
            applications = data["application-list"]["application"]
            for config_app in self.config["dos_attack"]["applications"]:
                for objects in applications:
                    if objects["_name"].lower() == config_app.lower():
                        if self.verbose:
                            cprint(
                                f"Applications:\n  {objects['_name']}\n  {objects['_id']}\n {objects['_description']}",
                                "magenta",
                            )
                        app_dict.append(objects["_id"])
                        app_name_dict.append(objects["_name"])
            return app_dict, app_name_dict

    def signal_handler(self, sig, frame):
        """Catch a CTRL-C for inspect results."""
        cprint(
            f"\nFinal mean byte count ==> {self.inspect_ave_bc}, {size(self.inspect_ave_bc)}",
            "green",
        )
        sys.exit(0)

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
        self.dos_baseline = self.config["dos_attack"]["dos_baseline"]
        app_ids, app_names = self.get_app_details()
        self.application_ids = {"includes": app_ids, "excludes": []}
        self.application_names = app_names

        # Set global config values from config file
        self.username = self.config["SMC"]["username"]
        self.password = self.config["SMC"]["password"]
        self.host = self.config["SMC"]["host"]
        self.tenant = self.config["SMC"]["tenant"]

    def dos_attack_vector(self):
        """Sequence a dDOS attack vector."""

        if not self.inspect:
            banner = (
                f"DDOS ATTACK VECTOR\n"
                f"Host: {self.host}\n"
                f"Tenant: {self.tenant}\n"
                f"Flow time queried: {self.dos_flow_time}s\n"
                f"Repeat every: {self.dos_flow_repeat_time}s\n"
                f"Percentage Warning Threshold: {self.dos_threshold}%\n"
                f"Configured Baseline Threshold: {size(self.dos_baseline)}\n"
                f"Application(s): {self.application_names}"
            )
        else:
            banner = (
                f"DDOS INSPECTION\n"
                f"Host: {self.host}\n"
                f"Tenant: {self.tenant}\n"
                f"Flow time queried: {self.dos_flow_time}s\n"
                f"Repeat every: {self.dos_flow_repeat_time}s\n"
                f"Application(s): {self.application_names}"
            )

        print_banner(
            banner, "magenta", ["bold"],
        )

        # Setup Pandas Series
        data_totals = pd.DataFrame(columns=["id"])
        data_totals_t = pd.DataFrame(columns=["AllBytes"])
        perc_change_df = pd.DataFrame(columns=["Byte_change"])

        inspect_loop_num = 0

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
                    "applications": self.application_ids,
                    "includeInterfaceData": "true",
                },
            }
            cprint(
                f"\n{self.dos_flow_time}s/{self.dos_flow_repeat_time}s probe -- "
                f"applications({self.application_ids}) flow request to: {self.host}",
                self.alert_color,
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

                # While search status incomplete, check the status every 5s
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

                # Normalize the data - remove flows layer
                new_data_active = pd.json_normalize(results, record_path="flows")

                # Empty results, unlikely - but just wait and try again
                if new_data_active.empty:
                    cprint("No new data", "magenta")
                    time.sleep(self.dos_flow_repeat_time)
                    print()
                    continue

                # Keep only these values
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
                (last_total_sum,) = [data_totals["TotalBytes"].sum()]
                data_totals_t.loc[len(data_totals_t)] = last_total_sum

                if self.verbose:
                    cprint(f"Total Protocol Bytes\n{data_totals_t}", self.alert_color)
                    print()

                # Will be displayed on program break
                self.inspect_ave_bc = data_totals_t["AllBytes"].mean().astype(int)

                #
                # Inspection mode
                #
                if self.inspect:
                    inspect_loop_num += 1
                    if self.verbose:
                        print(data_totals_t)
                    cprint(f"Request {inspect_loop_num}: ", "magenta")
                    cprint(f"New Total Bytes: {size(last_total_sum)}", "yellow")
                    cprint(
                        f"Average Byte Count: {size(self.inspect_ave_bc)}", "blue",
                    )
                    time.sleep(self.dos_flow_repeat_time)
                    continue

                #
                # Alerting mode
                #

                #
                # GREEN '0'
                #
                if self.alert_color == "green":
                    # If self.dos_baseline is set, use that as the baseline byte
                    # amount, of it is not set calculate it continuously from
                    # requests in the alert request loop.
                    if self.dos_baseline != 0:
                        # Percentage change between the last recorded total and
                        # the configured baseline
                        new_byte_perc = round(get_percent_change(last_total_sum, self.dos_baseline))
                        if self.verbose:
                            print(
                                f"Configured baseline: {size(last_total_sum)}, {size(self.dos_baseline)}, {new_byte_perc}%"
                            )
                    else:
                        # Calculate the percentage change between the latest and the
                        # last entry. This is way more subject to spurious changes.
                        perc_change_df = data_totals_t.pct_change() * 100
                        perc_change_df.columns = [
                            "Byte_change",
                        ]
                        perc_change_df = perc_change_df.round(2)
                        perc_change_df["Byte_change"] = perc_change_df["Byte_change"].fillna(0)
                        new_byte_perc = perc_change_df.tail(1)["Byte_change"]
                        new_byte_perc = new_byte_perc.iloc[0]

                        # dos baseline not configured so attempt to figure
                        # it out based on all the data we have
                        self.dos_baseline = last_total_sum

                    if new_byte_perc >= self.dos_threshold:
                        # Percentage change was greater than the configured
                        # threshold baseline
                        self.alert_color = "yellow"
                        self.alert_level = 5  # Highest level of Yellow

                        print_banner(
                            f"Status Yellow:\nProtocol Byte percentage change: {new_byte_perc}% >= "
                            f"Byte percentage threshold: {self.dos_threshold}%\n"
                            f"New bytes: {size(last_total_sum)}\n"
                            f"Threshold baseline bytes: {size(self.dos_baseline)}\n"
                            f"Current mean bytes: {size(self.inspect_ave_bc)}\n"
                            f"Alert level: '{self.alert_level}'\n"
                            f"Status level: '{self.alert_color}'",
                            self.alert_color,
                        )
                    else:
                        cprint(
                            f"{status_change(last_total_sum, self.dos_baseline)}\n"
                            f"Byte percentage change: {new_byte_perc}% < Byte percentage threshold "
                            f"{self.dos_threshold}%\n"
                            f"Current mean bytes: {size(self.inspect_ave_bc)}\n"
                            f"Alert level: '{self.alert_level}'\n"
                            f"Status level: '{self.alert_color}'",
                            self.alert_color,
                        )

                #
                # YELLOW 1-5
                #
                elif self.alert_color == "yellow":
                    # Look for 5 repeats below the dos_baseline
                    if last_total_sum < self.dos_baseline:
                        self.alert_level -= 1
                    elif last_total_sum > self.dos_baseline:
                        self.alert_level += 1

                    # Check if status should change to green or red
                    if self.alert_level < 1:
                        # Back to Green status
                        self.alert_level = 0  # Probably not needed
                        self.alert_color = "green"
                        print_banner(
                            f"Threshold Warning over\nLast total byte count: {size(last_total_sum)}\n"
                            f"Threshold baseline bytes reset\nAlert level: '{self.alert_level}'",
                            self.alert_color,
                        )
                    elif self.alert_level == 10:
                        # Up to Red status
                        self.alert_color = "red"
                        print_banner(
                            f"Status Red:\n"
                            f"Current mean bytes: {size(self.inspect_ave_bc)}\n"
                            f"Alert level: '{self.alert_level}'\n"
                            f"Status level: '{self.alert_color}'",
                            self.alert_color,
                        )
                    else:
                        # Within the Yellow range and staying Yellow - just report
                        cprint(
                            f"{status_change(last_total_sum, self.dos_baseline)}\n"
                            f"Current mean bytes: {size(self.inspect_ave_bc)}\n"
                            f"Alert level: '{self.alert_level}'\n"
                            f"Status level: '{self.alert_color}'",
                            self.alert_color,
                        )

                #
                # RED 10
                #
                elif self.alert_color == "red":
                    # We're in highest category of alert - can we move to
                    # yellow by dropping below 5?
                    if last_total_sum < self.dos_baseline:
                        self.alert_level -= 1
                    elif last_total_sum >= self.dos_baseline:
                        self.alert_level += 1
                        self.alert_level = min(self.alert_level, 10)

                    if self.alert_level < 10:
                        # Red alert over - reset to yellow
                        self.alert_color = "yellow"
                        print_banner(
                            f"Threshold Alert over, Last total {last_total_sum}\n"
                            f"Threshold baseline bytes {size(self.dos_baseline)}\n"
                            f"Current mean bytes: {size(self.inspect_ave_bc)}\n"
                            f"Alert level: '{self.alert_level}'\n"
                            f"Status level: '{self.alert_color}'",
                            self.alert_color,
                        )
                    else:
                        # Within the Red range and staying Red - just report
                        cprint(
                            f"{status_change(last_total_sum, self.dos_baseline)}\n"
                            f"Current mean bytes: {size(self.inspect_ave_bc)}\n"
                            f"Alert level: '{self.alert_level}'\n"
                            f"Status level: '{self.alert_color}'",
                            self.alert_color,
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
