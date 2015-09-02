#!/bin/env python
import sys
import re
from datetime import datetime

class FileInput(object):
    def __init__(self, file):
        self.file = file
    def __enter__(self):
        return self
    def __exit__(self,*args,**kwargs):
        self.file.close()
    def __iter__(self):
        return self
    def next(self):
        line = self.file.readline()
        if line == None or line == "":                                          
            raise StopIteration                                                 
        return line

TYPE_INIT="INIT" #init
TYPE_HEADER_EMPTY="TCP_STATUS" #tcp header line ,NO data
TYPE_HEADER_PSH="TCP_PUSH_DATA" #tcp package with data
TYPE_DATA_HTTPREQ="DATA_REQUEST" #data HTTP_REQ
TYPE_DATA_HTTPRESP="DATA_RESPONSE" #data HTTP_RESP

class TDFields(object):
    """Documentation for TDFields

    """
    def __init__(self, line):
        super(TDFields, self).__init__()
        self.line = line
        self.TYPE = TYPE_INIT
        self.src_host = ""
        self.dest_host = ""
        self.length = ""
        self.dt = ""
        try:
            self.parse()
        except Exception:
            pass
    def __str__(self):
        return "<Class TDFields> %s,%s,%s,%s,%s" % (self.TYPE,self.src_host,self.dest_host,self.length,self.dt)
    def type(self):
        return self.TYPE
    def tcpHeader(self):
        return self.TYPE == TYPE_HEADER_PSH or self.TYPE == TYPE_HEADER_EMPTY
    def tcpPSH(self):
        return self.TYPE == TYPE_HEADER_PSH
    def httpREQ(self):
        return self.TYPE == TYPE_DATA_HTTPREQ
    def httpRESP(self):
        return self.TYPE == TYPE_DATA_HTTPRESP
    
    def parse(self):
        ##parse tcp header
        tcp_pattern="(?P<time>[0-9]{2}:[0-9]{2}:[0-9]{2}.[0-9]{6}) IP (?P<src_host>[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{2,6}) > (?P<dest_host>[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{2,6}): .* (?P<length>[0-9]{1,})"
        result = re.match(tcp_pattern,self.line)
        if result:
            self.times=result.group("time")
            self.src_host = result.group("src_host")
            self.dest_host = result.group("dest_host")
            self.length = result.group("length")
            self.dt = datetime.strptime("%s" % self.times, "%H:%M:%S.%f")
            if int(self.length):
                self.TYPE=TYPE_HEADER_PSH
            else:
                self.TYPE=TYPE_HEADER_EMPTY
        else:
            #parse data
            req_result = re.match('.*(GET|POST|HEAD|DELETE) [^ ]* HTTP/[0-9].[0-9]',self.line)
            if req_result:
                self.TYPE=TYPE_DATA_HTTPREQ
            resp_result = re.match(".*HTTP/[0-9].[0-9] [0-9]{3} [A-Z]{2,}",self.line)
            if resp_result:
                self.TYPE=TYPE_DATA_HTTPRESP
 
class TDDark(object):
    __slots__=['waitqueue','fd']
    def __init__(self,fd):
        super(TDDark, self).__init__()
        self.fd=fd
        self.waitqueue={}
    def run(self):
        _last_tcphead = None
        for line in self.fd:
            tdf=TDFields(line)
            if tdf.tcpHeader():
                _last_tcphead = tdf
            if tdf.httpREQ():
                self.waitqueue.setdefault("%s > %s" % (_last_tcphead.src_host,_last_tcphead.dest_host),[]).append(_last_tcphead)
            if tdf.httpRESP():
                key="%s > %s" % (_last_tcphead.dest_host,_last_tcphead.src_host)
                _total_tdfs=self.waitqueue.get(key,[])
                if len(_total_tdfs):
                    _tdf=_total_tdfs.pop(0)
                    print key,_tdf.times,_last_tcphead.times,(_last_tcphead.dt-_tdf.dt).microseconds/1000.0
                    if len(_total_tdfs) == 0:
                        self.waitqueue.pop(key,[])
                        
def main():
    #for line in FileInput(sys.stdin):
    #    print line
    # line="16:55:52.640073 IP 101.251.204.125.80 > 123.151.138.111.33762: Flags [P.], seq 7074713:7075659, ack 2494081, win 400, options [nop,nop,TS val 1252162638 ecr 3658796879], length 946"
    # tf=TDFields(line)
    # print tf
    TDDark(FileInput(sys.stdin)).run()
    
if __name__ == '__main__':
    main()
    
