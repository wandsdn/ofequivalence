#!/usr/bin/python

# Copyright 2019 Richard Sanger, Wand Network Research Group
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3
from ryu.controller import dpset
from ryu.controller.handler import set_ev_cls
from ryu.app.ofctl import api
try:
    import cPickle as pickle
except ImportError:
    import pickle

class MatchTTP(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'dpset': dpset.DPSet}
    done = False

    def __init__(self, *args, **kwargs):
        super(MatchTTP, self).__init__(*args, **kwargs)
        self.collection = {}
        self.dpset = kwargs['dpset']

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def handle_datapath(self, ev):
        if not ev.enter or self.done:
            print('Skipping')
            return
        self.done = True
        dp = ev.dp
        parser = dp.ofproto_parser

        print('Switch connected')
        print('Collecting')

        # Request switch features XXX TODO FAILING
        try:
            msg = parser.OFPFeaturesRequest(dp)
            res = api.send_msg(self, msg, reply_cls=parser.OFPSwitchFeatures)
            self.collection['switch_features'] = res.to_json() if res else res
            print('Switch Features')
        except Exception as e:
            print("Exception collecting Switch Features")
            print(e)

        # Request config - non multipart
        try:
            msg = parser.OFPGetConfigRequest(dp)
            res = api.send_msg(self, msg, reply_cls=parser.OFPGetConfigReply)
            self.collection['config'] = ({"flags": res.flags,
                                          "miss_send_len": res.miss_send_len}
                                         if res else res)
            print('Switch Config')
        except Exception as e:
            print("Exception collecting Switch Config")
            print(e)

        # Request switch description - multipart single item
        try:
            msg = parser.OFPDescStatsRequest(dp)
            res = api.send_msg(self, msg, reply_cls=parser.OFPDescStatsReply,
                               reply_multi=True)
            if len(res) != 1:
                raise Exception(('Expecting only a single response from'
                                 ' switch description', res))
            self.collection['desc'] = res[0].body
            print('Switch Description')
        except Exception as e:
            print("Exception collecting Switch Descripton")
            print(e)

        # Request all stats from all tables - multipart list
        try:
            msg = parser.OFPFlowStatsRequest(dp)
            res = api.send_msg(self, msg, reply_cls=parser.OFPFlowStatsReply,
                               reply_multi=True)
            l = [stat for stats in res for stat in stats.body]
            self.collection['flow_stats'] = l
            print('Flows Stats')
        except Exception as e:
            print("Exception collecting Flow Stats")
            print(e)

        # Request table stats - multipart list
        try:
            msg = parser.OFPTableStatsRequest(dp)
            res = api.send_msg(self, msg, reply_cls=parser.OFPTableStatsReply,
                               reply_multi=True)
            l = [table for tables in res for table in tables.body]
            self.collection['table_stats'] = l
            print('Table Stats')
        except Exception as e:
            print("Exception collecting Table Stats")
            print(e)

        # Request port stats - multipart list
        try:
            msg = parser.OFPPortStatsRequest(dp)
            res = api.send_msg(self, msg, reply_cls=parser.OFPPortStatsReply,
                               reply_multi=True)
            l = [port for ports in res for port in ports.body]
            self.collection['port_stats'] = l
            print('Port Stats')
        except Exception as e:
            print("Exception collecting Port Stats")
            print(e)

        # Request port descriptions - multipart list
        try:
            msg = parser.OFPPortDescStatsRequest(dp)
            res = api.send_msg(self, msg,
                               reply_cls=parser.OFPPortDescStatsReply,
                               reply_multi=True)
            l = [port for ports in res for port in ports.body]
            self.collection['port_desc'] = l
            print('Port Description')
        except Exception as e:
            print("Exception collecting Port Description")
            print(e)

        # Request queue stats - mulitpart list
        try:
            msg = parser.OFPQueueStatsRequest(dp)
            res = api.send_msg(self, msg, reply_cls=parser.OFPQueueStatsReply,
                               reply_multi=True)
            l = [queue for queues in res for queue in queues.body]
            self.collection['queue_stats'] = l
            print('Queue Stats')
        except Exception as e:
            print("Exception collecting Queue Stats")
            print(e)

        # Request group stats - multipart list
        try:
            msg = parser.OFPGroupStatsRequest(dp)
            res = api.send_msg(self, msg, reply_cls=parser.OFPGroupStatsReply,
                               reply_multi=True)
            l = [group for groups in res for group in groups.body]
            self.collection['group_stats'] = l
            print('Group Stats')
        except Exception as e:
            print("Exception collecting Group Stats")
            print(e)

        # Request group desc - multipart list
        try:
            msg = parser.OFPGroupDescStatsRequest(dp)
            res = api.send_msg(self, msg,
                               reply_cls=parser.OFPGroupDescStatsReply,
                               reply_multi=True)
            l = [group for groups in res for group in groups.body]
            self.collection['group_desc'] = l
            print('Group Description')
        except Exception as e:
            print("Exception collecting Group Description")
            print(e)

        # Request group features - multipart single item
        try:
            msg = parser.OFPGroupFeaturesStatsRequest(dp)
            res = api.send_msg(self, msg,
                               reply_cls=parser.OFPGroupFeaturesStatsReply,
                               reply_multi=True)
            if len(res) != 1:
                raise Exception(('Expecting only a single response from'
                                 ' group features', res))
            self.collection['group_features'] = res[0].body
            print('Group Features')
        except Exception as e:
            print("Exception collecting Group Features")
            print(e)

        # Request meter stats - multipart list
        try:
            msg = parser.OFPMeterStatsRequest(dp)
            res = api.send_msg(self, msg, reply_cls=parser.OFPMeterStatsReply,
                               reply_multi=True)
            l = [meter for meters in res for meter in meters.body]
            self.collection['meter_stats'] = l
            print('Meter Stats')
        except Exception as e:
            print("Exception collecting Meter Stats")
            print(e)

        # Request meter config - multipart list
        try:
            msg = parser.OFPMeterConfigStatsRequest(dp)
            res = api.send_msg(self, msg,
                               reply_cls=parser.OFPMeterConfigStatsReply,
                               reply_multi=True)
            l = [meter for meters in res for meter in meters.body]
            self.collection['meter_config'] = l
            print('Meter Config')
        except Exception as e:
            print("Exception collecting Meter Config")
            print(e)

        # Request meter features - single item
        try:
            msg = parser.OFPMeterFeaturesStatsRequest(dp)
            res = api.send_msg(self, msg,
                               reply_cls=parser.OFPMeterFeaturesStatsReply,
                               reply_multi=True)
            if len(res) != 1:
                raise Exception(('Expecting only a single response from'
                                 ' meter features', res))
            self.collection['meter_features'] = res[0].body
            print('Meter Features')
        except Exception as e:
            print("Exception collecting Meter Features")
            print(e)

        # Request table features, this can be very large
        try:
            msg = parser.OFPTableFeaturesStatsRequest(dp)
            res = api.send_msg(self, msg,
                               reply_cls=parser.OFPTableFeaturesStatsReply,
                               reply_multi=True)
            l = [table for tables in res for table in tables.body]
            self.collection['table_features'] = l
            print('Table Features')
        except Exception as e:
            print("Exception collecting Table Features")
            print(e)

        # Request queue config (this is done on a per port basis) so
        # querying all does not work so well.
        # Not multipart!?
        try:
            msg = parser.OFPQueueGetConfigRequest(dp, ofproto_v1_3.OFPP_ANY)
            res = api.send_msg(self, msg,
                               reply_cls=parser.OFPQueueGetConfigReply)
            self.collection['queue_config'] = res.queues if res else res
            print('Queue Config')
        except Exception as e:
            print("Exception collecting Queue Config")
            print(e)

        pickle.dump(self.collection, open("switch_state.pickle", "wb"))
        print('Switch dumped successfully')

if __name__ == '__main__':
    print("This is a ryu app that passively collects all stats, features"
          " and configurations to capture the current state of a running"
          " OpenFlow Switch v1.3. This includes all flows, groups, queues,"
          " meters, ports.\n")
    print("The output is written to switch_state.pickle as pickled a"
          " dictionary of ryu objects")
    print("Run as:")
    print ("ryu-mananger --ofp-tcp-listen-port <port> --ofp-listen-host <host>"
           " --log-config-file <./log.conf> ./CollectState.py")
