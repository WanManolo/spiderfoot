# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_haveibeenpwned_domain_breach
# Purpose:      Query haveibeenpwned.com to see if a domain has been breached.
#
# Author:      Juan Manuel Rodríguez Trillo <oneman.rt@gmail.com>
#
# Created:     24/01/2022
# Copyright:   (c) Juan Manuel Rodríguez Trillo 2022
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_haveibeenpwned_domain_breach(SpiderFootPlugin):

    meta = {
        'name': "HaveIBeenPwned Domain Breaches",
        'summary': "Check HaveIBeenPwned.com for domain names to confirm there is a public breach.",
        'flags': [""],
        'useCases': ["Investigate", "Breach", "Passive", "Leak"],
        'categories': ["Passive DNS"],
        'dataSource': {
            'website': "https://haveibeenpwned.com/",
            'model': "FREE",
            'references': [
                "https://haveibeenpwned.com/API/v3",
                "https://haveibeenpwned.com/FAQs"
            ],
            'favIcon': "https://haveibeenpwned.com/favicon.ico",
            'logo': "https://haveibeenpwned.com/favicon.ico",
            'description': "Check if there is any public data breach for the given domain name.",
        }
    }

    # Default options
    opts = {
    }

    # Option descriptions
    optdescs = {
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["DOMAIN_NAME", "DOMAIN_NAME_PARENT", "CO_HOSTED_SITE_DOMAIN",
                "AFFILIATE_DOMAIN_NAME", "SIMILARDOMAIN"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["DOMAIN_NAME"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        try:
            self.sf.debug(f"We use the data: {eventData}")
            print(f"We use the data: {eventData}")

            data = self.query(eventData)
            if data is not None:
                for n in data:
                    try:
                        site = n["Name"]
                    except Exception as e:
                        self.debug(
                            f"Unable to parse result from HaveIBeenPwned?: {e}")
                        continue

                    # Notify other modules of what we've found
                    if eventName in self.watchedEvents():
                        e = SpiderFootEvent("DOMAIN_NAME", eventData + " [" + site + "]",
                                            self.__name__, event)
                    if e is not None:
                        self.notifyListeners(e)

            if not data:
                self.sf.error(
                    "Unable to query HaveIBeenPwned on " + eventData)
                return
        except Exception as e:
            self.sf.error(
                "Unable to query HaveIBeenPwned on " + eventData + ": " + str(e))
            return

    def query(self, qry):
        url = f"https://haveibeenpwned.com/api/v3/breaches?domain={qry}"
        hdrs = {"Accept": f"application/vnd.haveibeenpwned.v3+json"}
        retry = 0

        while retry < 2:
            # https://haveibeenpwned.com/API/v3#RateLimiting
            time.sleep(1.5)
            res = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'],
                                   useragent="SpiderFoot", headers=hdrs)

            if res['code'] == "200":
                break

            if res['code'] == "404":
                return None

            if res['code'] == "429":
                # Back off a little further
                time.sleep(2)
            retry += 1

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.error(
                f"Error processing JSON response from HaveIBeenPwned?: {e}")

        return None

# https://haveibeenpwned.com/api/v3/breaches?domain=adobe.com

# End of sfp_haveibeenpwned_domain_breach class
