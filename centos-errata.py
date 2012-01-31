#!/usr/bin/python

# Script which can process CentOS errata announcements and convert
# them to errata in spacewalk.  Based on rhn-tool.py by Lars Jonsson
#
# Latest version of the script may be obtained from
# http://www.bioss.ac.uk/staff/davidn/spacewalk-stuff/
#
# Copyright (C) 2012  Biomathematics and Statistics Scotland
#
# Author: Lars Jonsson (ljonsson@redhat.com)
#         David Nutter (davidn@bioss.ac.uk)
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
#

from datetime import datetime
from optparse import OptionParser
import ConfigParser
import email
import getpass
import libxml2
import lxml.html
import os
import re
import rpm
import sys
import traceback
import urllib
import xmlrpclib

class RHNSystem:
    def __init__(self,sysid,name,lastCheckin):
        self.systemid=sysid
        self.name=name
        self.lastCheckin=lastCheckin

class RHNErrata:

    SECURITY='Security Advisory'
    ENHANCEMENT='Product Enhancement Advisory'
    BUGFIX='Bug Fix Advisory'
    
    def __init__(self):
        self.synopsis = None
        self.advisoryName = None
        self.advisoryRelease = 1
        self.advisoryType = RHNErrata.SECURITY
        self.product = None
        self.topic = None
        self.description = None
        self.references = ""
        self.notes = ""
        self.solution = None

        self.publish = False

        self.channelLabel = []
        
        self.keywords=[]
        self.bugs=[]
        self.packages=[]

        self.issueDate = datetime.now()
        self.modifiedDate = datetime.now()
        self.updateDate = datetime.now()

        #This is used internally by the script
        self.x_isFastTrack = False

    def getPackageIds(self):
        result=map((lambda pkg: pkg.id),self.packages)
        return result
    
    def getInfoDict(self):
        result={}
        result['synopsis']=self.synopsis
        result['advisory_name']=self.advisoryName
        result['advisory_release']=self.advisoryRelease        
        result['advisory_type']=self.advisoryType
        result['product']=self.product
        result['topic']=self.topic
        result['description']=self.description
        result['references']=self.references
        result['notes']=self.notes
        result['solution']=self.solution                
        return result

    def readyToCreate(self):
        info = self.getInfoDict()
        for required_attr in ['synopsis','advisory_name','advisory_release','advisory_type','product','topic','description','solution']:
            if info[required_attr] is None:
                return False

        return True

    def addPublishChannel(self,new_channel_label):
        try:
            self.channelLabel.index(new_channel_label)
            return False
        except:
            self.channelLabel.append(new_channel_label)
            return True

    def clone(self):
        ret = RHNErrata()
        
        ret.synopsis        = self.synopsis
        ret.advisoryName    = self.advisoryName
        ret.advisoryRelease = self.advisoryRelease
        ret.advisoryType    = self.advisoryType
        ret.product         = self.product
        ret.topic           = self.topic
        ret.description     = self.description
        ret.references      = self.references
        ret.notes           = self.notes
        ret.solution        = self.solution

        ret.publish         = self.publish

        #We shallow copy our list members
        ret.channelLabel    = list(self.channelLabel)
        ret.keywords        = list(self.keywords)
        ret.bugs            = list(self.bugs)
        ret.packages        = list(self.packages)

        ret.issueDate       = self.issueDate
        ret.modifiedDate    = self.modifiedDate
        ret.updateDate      = self.updateDate

        ret.x_isFastTrack   = self.x_isFastTrack
        ret.x_arch          = self.x_arch
        ret.x_packageDir    = self.x_packageDir
        
        return ret
    
    def printOut(self):
        print "%-20s = %s" % ("Name:",self.advisoryName)
        print "%-20s = %s" % ("Release:",self.advisoryRelease)
        print "%-20s = %s" % ("Product:",self.product)
        print "%-20s = %s" % ("Synopsis:",self.synopsis)
        print "%-20s = %s" % ("Topic:",self.topic)
        print "%-20s = %s" % ("Description:",self.description)
        print "%-20s = %s" % ("Solution:",self.solution)
        print "%-20s = %s" % ("Notes:",self.notes)

        for channel in self.channelLabel:
            print "%-20s = %s" % ("Target Channel:",channel)

        for pkg in self.packages:
            print "  Package: %s" % pkg.getNVRA()

class RHNPackage:
    def __init__(self,name,version,release,epoch,archLabel):
        self.id = None
        self.name = name
        self.version = version
        self.release = release
        self.epoch = epoch
        self.archLabel = archLabel
        self.path = None
        self.provider = None
        self.lastModified = datetime.today()

    #TODO: add epoch to this, if present, rename method
    def getNVRA(self):
        result = "%s-%s-%s.%s" % (self.name,self.version,self.release,self.archLabel)
        return result

class RHNTaskoBunch:
    def __init__(self,name,description,template_names):
        self.bunchName=name
        self.bunchDesc=description
        self.templateNames=template_names


    def printOut(self):
        print "%-20s = %s" % ("Name:",self.bunchName)
        print "%-20s = %s" % ("Description:",self.bunchDesc)

        for template in self.templateNames:
            print "%-20s = %s" % ("  Template:",template)

class RHNTaskoSchedule:
    def __init__(self,id,bunch_name,job_label,active_from,active_to):
        self.id = id
        self.bunchName = bunch_name
        self.jobLabel = job_label
        self.activeFromDate = active_from
        self.activeToDate = active_to

    def printOut(self):
        print "%-20s = %s" % ("ID:",self.id)
        print "%-20s = %s" % ("Bunch Name:",self.bunchName)
        print "%-20s = %s" % ("Job Label:",self.jobLabel)
    
class RHNSession:
    def __init__(self, servername, user, password):
        self.rhnServerName = servername
        self.login = user
        self.password = password
        self.rhnUrl = 'https://'+self.rhnServerName+'/rpc/api'
        self.server = xmlrpclib.Server(self.rhnUrl)
        self.rhnSessionKey=self.rhnLogin(self.login,self.password)

    @staticmethod
    def addRequiredOptions(parser):
        parser.add_option("-s", "--server", type="string", dest="server",
                          help="RHN Satellite server hostname")
        parser.add_option("-l", "--login", type="string", dest="login",
                          help="RHN Login") 
        parser.add_option("", "--password", type="string", dest="password",
                          help="RHN password (cleartext)") 

    @staticmethod
    def establishSession(options,cmdName):
        if (options.server and options.login) is None:
            print "Please specify --server and --login. Try: "+cmdName+" --help"
            sys.exit(2)

        try:
            while options.password is None:
                options.password = getpass.getpass("RHN Password: ")   
        except Exception, e:
            print "Terminal does not seem to be functional. You should specify a password with --password. Aborting."
            sys.exit(2)

        mySession = RHNSession(options.server,options.login,options.password)
        return mySession

    def rhnLogin(self, login, password): 
        try:
            rhnSessionKey=self.server.auth.login(login,password)
        except  xmlrpclib.Fault, f:
            if f.faultCode==-20:
                print "Session expired"
                self.rhnLogin(login,password)
            else:
                print "Failed to login",f
                raise
        return rhnSessionKey

    def getSystemByName(self,profileName):
        out=[]
        try:
            out=self.server.system.getId(self.rhnSessionKey,profileName)                
        except  xmlrpclib.Fault, f:
            if f.faultCode==-20:
                self.rhnLogin(self.login,self.password)
                return self.getSystemByName(profileName)
            else:
                raise

        systemObj=None
        if (len(out) > 0):
            systemObj = RHNSystem(out[0]['id'],out[0]['name'],out[0]['last_checkin'])
        return systemObj    
        

    def getSystemByID(self,systemid):
        out=[]
        try:
            out = self.server.system.getName(self.rhnSessionKey,systemid)
        except xmlrpclib.Fault, f:
            if f.faultCode==-20:
                self.rhnLogin(self.login,self.password)
                return self.getSystemByID(systemid)
            else:
                raise

        systemObj=None
        if (len(out) > 0):
            systemObj = RHNSystem(out[0]['id'],out[0]['name'],out[0]['last_checkin'])
        return systemObj

    def getThisMachine(self):
       out=[]
       try:
           p = libxml2.parseDoc(file("/etc/sysconfig/rhn/systemid").read())
           systemid = p.xpathEval('string(//member[* = "system_id"]/value/string)').split('-')[1]
       except IOError:
           print "systemid file not found."
           raise

       systemObj = self.getSystemByID(systemid)
       return systemObj


    #TODO: this should probably return an object rather than a dictionary
    def getSystemDetails(self,systemObj):
        out={}
        try:
            out=self.server.system.getDetails(self.rhnSessionKey,int(systemObj.systemid))
        except xmlrpclib.Fault, f:
            if f.faultCode==-20:
                self.rhnLogin(self.login,self.password)
                return self.getSystemDetails(systemObj)
            else:
                raise

        return out

    def listGroups(self,systemObj):
        out=[]
        try:
            out=self.server.system.listGroups(self.rhnSessionKey,int(systemObj.systemid))
        except  xmlrpclib.Fault, f:
            if f.faultCode==-20:
                self.rhnLogin(self.login,self.password)
                return self.listGroups(systemObj)
            else:
                raise
        return out

    def listUserSystems(self):
        out=[]
        try:
            out=self.server.system.listUserSystems(self.rhnSessionKey)
        except  xmlrpclib.Fault, f:
            if f.faultCode==-20:
                self.rhnLogin(self.login,self.password)
                return self.listUserSystems()
            else:
                raise

        if (len(out) > 0):
            out2=[]
            for sys_info in out:
                sys_obj=RHNSystem(sys_info['id'],sys_info['name'],sys_info['last_checkin'])
                out2.append(sys_obj)

            out=out2
        return out

    def listActivationKeys(self):
        out=[]
        try:
            out=self.server.activationkey.listActivationKeys(self.rhnSessionKey)
        except  xmlrpclib.Fault, f:
            if f.faultCode==-20:
                self.rhnLogin(self.login,self.password)
                return self.listActivationKeys()
            else:
                raise
        return out

    def deleteSystems(self,systemObj):
        out=[]
        try:
            out=self.server.system.deleteSystems(self.rhnSessionKey,systemObj.systemid)
        except  xmlrpclib.Fault, f:
            if f.faultCode==-20:
                self.rhnLogin(self.login,self.password)
                return self.deleteSystems(systemObj)
            else:
                raise
        return out

    def setGroupMembership(self,systemObj,groupid,join):
        out=[]
        try:
            out = self.server.system.setGroupMembership(self.rhnSessionKey,int(systemObj.systemid),groupid,join)
        except  xmlrpclib.Fault, f:
            if f.faultCode==-20:
                self.rhnLogin(self.login,self.password)
                return self.setGroupMembership(systemObj,groupid,join)
            else:
                raise
        return out

    def addNote(self,systemObj,label,msg):
        out=[]
        try:
            out = self.server.system.addNote(self.rhnSessionKey,int(systemObj.systemid),label,msg)
        except  xmlrpclib.Fault, f:
            if f.faultCode==-20:
                self.rhnLogin(self.login,self.password)
                return self.addNote(systemObj,label,msg)
            else:
                raise
        return out
        
    def setCustomValues(self,systemObj,customInfoDict):
        out=[]
        if not customInfoDict is None:
            try:
                out = self.server.system.setCustomValues(self.rhnSessionKey,int(systemObj.systemid),customInfoDict)
            except  xmlrpclib.Fault, f:
                if f.faultCode==-20:
                    self.rhnLogin(self.login,self.password)
                    return self.setCustomValues(systemObj,customInfoDict)
                else:
                    raise
        return out

    def setCustomValue(self,systemObj,label,value):
        customInfoArgs={label:value[0]}
        return self.setCustomValues(systemObj,customInfoArgs)
    
    def setSystemDetails(self,systemObj,detailsDict):
        out=0
        if not detailsDict is None:
            try:
                out = self.server.system.setDetails(self.rhnSessionKey,int(systemObj.systemid),detailsDict)
            except xmlrpclib.Fault, f:
                if f.faultCode==-20:
                    self.rhnLogin(self.login,self.password)
                    return self.setSystemDetails(systemObj,detailsDict)
                else:
                    raise
        return out
        
    def setNewProfileName(self,systemObj,name):
        out=[]
        try:
            systemObj.name=name
            out = self.server.system.setProfileName(self.rhnSessionKey,int(systemObj.systemid),name)
        except  xmlrpclib.Fault, f:
            if f.faultCode==-20:
                self.rhnLogin(self.login,self.password)
                return self.setProfileName(systemObj,name)
            else:
                raise
        return out

    def setGroup(self, systemObj, groupname, join=1): 
        for c in self.listGroups():
            if c['system_group_name'] == groupname:
                sgid=c['sgid']
                if int(c['subscribed']) == 1:
                    join = 0
                if join == 1:
                    self.setGroupMembership(systemObj, int(sgid),join)
                    print "System %s has joined %s " % systemObj.name, groupname
                else:
                    self.setGroupMembership(systemObj, int(sgid),join)
                    print "System %s has left %s" % systemObj.name, groupname

    def getCustomValues(self,systemObj):
        out={}
        try:
            out = self.server.system.getCustomValues(self.rhnSessionKey,int(systemObj.systemid))
        except  xmlrpclib.Fault, f:
            if f.faultCode==-20:
                self.rhnLogin(self.login,self.password)
                return self.getCustomKeyLabels()
            else:
                raise
        return out

    def addCustomKey(self,keyLabel,keyDescription):
        out=0
        try:
            out = self.server.system.custominfo.createKey(self.rhnSessionKey,keyLabel,keyDescription)
        except  xmlrpclib.Fault, f:
            if f.faultCode==-20:
                self.rhnLogin(self.login,self.password)
                return self.addCustomKey(keyLabel,keyDescription)
            else:
                raise
        return out
    
    def getCustomKeyLabels(self):
        out=set()
        result=[]
        try:
            result = self.server.system.custominfo.listAllKeys(self.rhnSessionKey)
        except  xmlrpclib.Fault, f:
            if f.faultCode==-20:
                self.rhnLogin(self.login,self.password)
                return self.getCustomKeyLabels()
            else:
                raise

        for keyInfo in result:
            out.add(keyInfo['label'])

        return out

    def getErrataDetails(self,advisoryName):
        result=None
        try:
            result = self.server.errata.getDetails(self.rhnSessionKey,advisoryName)
        except  xmlrpclib.Fault, f:
            if f.faultCode==-20:
                self.rhnLogin(self.login,self.password)
                return self.getErrataDetails(advisoryName)
            elif f.faultCode==-208: #This seems to be the fault returned when the errata does not exist
                result = None                
            else:
                raise

        if not result is None:
            errata = RHNErrata()
            errata.advisoryName=advisoryName
            errata.issueDate = result['issue_date']
            errata.modifiedDate = result['update_date']
            errata.updateDate = result['last_modified_date']
            errata.description=result['description']
            errata.synopsis=result['synopsis']
            errata.topic=result['topic']
            errata.references=result['references']
            errata.notes=result['notes']
            errata.advisoryType=result['type']
        else:
            errata = None

        return errata

        
    
    def findPackageByNVREA(self,pkg_info):
        result= None
        pkg_details = None
        try:
            #Fortunately this RPC method returns an empty list if the package does not exist, no need to handle an undocumented exception
            if pkg_info.epoch:
                result = self.server.packages.findByNvrea(self.rhnSessionKey,pkg_info.name,pkg_info.version,pkg_info.release,pkg_info.epoch,pkg_info.archLabel)
            else:
                result = self.server.packages.findByNvrea(self.rhnSessionKey,pkg_info.name,pkg_info.version,pkg_info.release,"",pkg_info.archLabel)

            if len(result) > 0:
                pkg_details = result[0]
                
        except  xmlrpclib.Fault, f:
            if f.faultCode==-20:
                self.rhnLogin(self.login,self.password)
                return self.findPackageByNVREA(pkg_info)
            else:
                raise

        
        if not pkg_details is None:
            server_pkg = RHNPackage(pkg_details['name'],pkg_details['version'],pkg_details['release'],pkg_details['epoch'],pkg_details['arch_label'])
            server_pkg.id = pkg_details['id']
            server_pkg.path = pkg_details['path']
            server_pkg.provider = pkg_details['provider']
            server_pkg.lastModified=pkg_details['last_modified']
            return server_pkg

        return None

    #BUG: this won't find packages with an epoch in the name
    def findPackageByNameAndChecksum(self,pkg_name, pkg_checksum):
        result= None
        pkg_details = None
        
        try:
            #Fortunately this RPC method returns an empty list if the package does not exist, no need to handle an undocumented exception
            result = self.server.packages.search.name(self.rhnSessionKey,pkg_name)

            if len(result) > 0:
                for search_result in result:
                    if pkg_name == search_result['name']:
                        pkg_details = self.server.packages.getDetails(self.rhnSessionKey,search_result['id'])
                                                
                        if pkg_details['checksum'] == pkg_checksum:
                            server_pkg = RHNPackage(pkg_details['name'],pkg_details['version'],pkg_details['release'],pkg_details['epoch'],pkg_details['arch_label'])
                            server_pkg.id = pkg_details['id']
                            server_pkg.path = pkg_details['path']
                            server_pkg.lastModified=pkg_details['last_modified_date']
                            return server_pkg
                        
                
        except  xmlrpclib.Fault, f:
            if f.faultCode==-20:
                self.rhnLogin(self.login,self.password)
                return self.findPackageByNameAndChecksum(pkg_name,pkg_checksum)
            else:
                raise

        return None

    def listScheduledBunches(self):
        result = []

        try:
            result = self.server.taskomatic.listActiveSatSchedules(self.rhnSessionKey)
        except  xmlrpclib.Fault, f:
            if f.faultCode==-20:
                self.rhnLogin(self.login,self.password)
                return self.listSchedueldBunches()
            else:
                raise

        if (len(result) > 0):
            result2=[]
            for sched_bunch in result:
                sched_obj=RHNTaskoSchedule(sched_bunch['id'],sched_bunch['bunch'],sched_bunch['job_label'],sched_bunch['active_from'],None)
                result2.append(sched_obj)
            return result2
        
        return None

    
    def listTaskomaticBunches(self):
        result = []
        
        try:
            result = self.server.taskomatic.listSatBunches(self.rhnSessionKey)                
        except  xmlrpclib.Fault, f:
            if f.faultCode==-20:
                self.rhnLogin(self.login,self.password)
                return self.listTaskomaticBunches()
            else:
                raise

        if (len(result) > 0):
            result2 = []
            for bunch in result:
                template_names=[]
                for template in bunch['templates']:
                    template_names.append(template['name'])
                    
                bunch_obj = RHNTaskoBunch(bunch['name'],bunch['description'],template_names)
                result2.append(bunch_obj)
                
            return result2
        return None

    def unscheduleTaskomaticBunch(self,job_label):
        result = None
        
        try:
            result = self.server.taskomatic.unscheduleSatBunch(self.rhnSessionKey,job_label)

            #TODO: do something sensible with this
            return result
        except  xmlrpclib.Fault, f:
            if f.faultCode==-20:
                self.rhnLogin(self.login,self.password)
                return self.unscheduleTaskomaticBunch(job_label)
            else:
                raise
        
        return None
        
    def createErrata(self,erratum):
        result= None

        #Note: this method has not been tested when the errata has any bugs or keywords. Sending the value [{}] for bugs seems to cause a crash - maybe you need [{id:"12345",name:"foobug"}] or similar for it to work
        if not erratum.readyToCreate():
            raise

        try:
                result = self.server.errata.create(self.rhnSessionKey,erratum.getInfoDict(),erratum.bugs,erratum.keywords,erratum.getPackageIds(),erratum.publish,erratum.channelLabel)
            
        except  xmlrpclib.Fault, f:
            if f.faultCode==-20:
                self.rhnLogin(self.login,self.password)
                return self.createErrata(erratum)
            else:
                raise

        return result

class ErrataCache:
    def __init__(self):
        self.templateErrata={}
        self.completeErrata={}

    def addTemplateErrata(self,erratum):
        self.templateErrata[erratum.advisoryName]=erratum
                
    def addCompleteErrata(self,errata_arch,erratum):
        if not self.completeErrata.has_key(errata_arch):
            self.completeErrata[errata_arch]={}
        self.completeErrata[errata_arch][erratum.advisoryName]=erratum

    def hasTemplateErrata(self,errata_name):
        return self.templateErrata.has_key(errata_name)
    
    def hasCompleteErrata(self,errata_arch,errata_name):
        if self.completeErrata.has_key(errata_arch):
            return self.completeErrata[errata_arch].has_key(errata_name)
        return False

    def getActiveArchitectures(self):
        return self.completeErrata.keys()

    def getCompleteErrata(self,errata_arch):
        if self.completeErrata.has_key(errata_arch):
            return self.completeErrata[errata_arch]
        return {}

class MessageAnnounce:

    def __init__(self,
                 errata_type=None,
                 errata_id=None,
                 errata_year=None,
                 errata_severity=None,
                 errata_synopsis=None,
                 errata_date=None,
                 centos_version=None,
                 msg_subject=None):
        
        self.packageByArch={}

        self.errataType=errata_type
        self.errataID=errata_id
        self.errataYear=errata_year
        self.errataSeverity=errata_severity
        self.errataSynopsis=errata_synopsis
        self.errataDate=errata_date
        
        self.centosVersion=centos_version
        self.messageSubject=msg_subject


    def isFastTrackMessage(self):
        if self.errataSynopis is not None:
            return self.errataSynopsis.find("FASTTRACK") > -1
        return False

    def getRHNUrl(self):
        rhn_url = "https://rhn.redhat.com/errata/%s-%s-%s.html" % (self.errataType,self.errataYear,self.errataID)
        rhn_url = re.sub(r"/CE","/RH",rhn_url)
        return rhn_url

    def getAdvisoryName(self):
        advisory_name="%s-%s:%s" % (self.errataType,self.errataYear,self.errataID) 
        return advisory_name

class MessagePackageInfo:

    def __init__(self,pkg_arch,pkg_checksum,pkg_file):
        self.architecture = pkg_arch
        self.checksum = pkg_checksum
        self.filename = pkg_file

class MessageParser(object):

    #Common regular expressions
    ARCH_SPLIT="(?P<arch>\w+):\s*$"
    PACKAGE_LIST="(?P<checksum>\S+)\s+(?P<pkg_filename>[\.\w-]+.rpm)"

    #Things to match in mailing list messages
    ERRATA_SUBJECT="\[CentOS-announce\] (?P<errata_type>\w{4,4})-(?P<year>\d{4,4})(:|-)(?P<errata_id>\d{4,4})\s+(?P<other_info>.*)$"
    SECURITY_INFO="(?P<severity>\w+) CentOS\s+(?P<version>\d)\s+(?P<synopsis>.*)$"
    BUG_INFO="CentOS\s+(?P<version>\d)\s+(?P<synopsis>.*)$"
    ENHANCE_INFO="CentOS\s+(?P<version>\d)\s+(?P<synopsis>.*)$"

    #Tags for the different advisory types
    SECURITY_ERRATA="CESA"
    BUG_ERRATA="CEBA"
    ENHANCE_ERRATA="CEEA"

    erratum_subject_re = re.compile(ERRATA_SUBJECT)
    sec_info_re = re.compile(SECURITY_INFO)
    bug_info_re = re.compile(BUG_INFO)
    enhance_info_re = re.compile(ENHANCE_INFO)
    arch_re = re.compile(ARCH_SPLIT)
    packagelist_re = re.compile(PACKAGE_LIST)

    def __init__(self,options):
        self.options=options
 
    #Chop up message into lists of packages per architecture and return
    def processPackageList(self,message_body):
        arch_packages={}

        current_arch = None
    
        for line in message_body.split('\n'):
            arch_match = MessageParser.arch_re.match(line)
            packagelist_match = MessageParser.packagelist_re.match(line)

            if not arch_match is None:            
                current_arch = arch_match.group('arch')
                arch_packages[current_arch]=list()
            elif not (current_arch is None or
                      packagelist_match is None):
                arch_packages[current_arch].append(
                    MessagePackageInfo(
                    current_arch,
                    packagelist_match.group('checksum'),
                    packagelist_match.group('pkg_filename')
                    )
                    )
                
        return arch_packages

    #Construct the basic details about the errata from the message subject
    def processMessageSubject(self,message_subject):
        erratum_subject_match =  MessageParser.erratum_subject_re.match(message_subject)
    
        if erratum_subject_match is None:
            print "Message with subject '%s' doesnt appear to be an errata " % message_subject
            return None

        parsed_msg = MessageAnnounce()
        parsed_msg.messageSubject = re.sub("\s+"," ",message_subject)            
        parsed_msg.errataType = erratum_subject_match.group('errata_type')
        parsed_msg.errataID = erratum_subject_match.group('errata_id')
        parsed_msg.errataYear = erratum_subject_match.group('year')

        if parsed_msg.errataType == MessageParser.SECURITY_ERRATA:
            info_match =  MessageParser.sec_info_re.match(erratum_subject_match.group('other_info'))
        elif parsed_msg.errataType == MessageParser.BUG_ERRATA:
            info_match = MessageParser.bug_info_re.match(erratum_subject_match.group('other_info'))
        elif parsed_msg.errataType == MessageParser.ENHANCE_ERRATA:
            info_match = MessageParser.enhance_info_re.match(erratum_subject_match.group('other_info'))
        else:
            print "Unknown errata type %s, assuming type BUG" % erratum_subject_match.group('errata_type')
            parsed_msg.errataType = BUG_ERRATA
            info_match = MessageParser.bug_info_re.match(erratum_subject_match.group('other_info'))

        if info_match is None:
            print "Errata '%s' doesnt match any of the known types " % erratum_subject 
            return None

        parsed_msg.centosVersion = info_match.group('version')            
        parsed_msg.errataSynopsis = info_match.group('synopsis').replace('\t', ' ')

        if parsed_msg.centosVersion != self.options.centos_version:
            print "Message '%s' is inapplicable to the targeted CentOS release " % parsed_msg.messageSubject
            return None

        if info_match.groupdict().has_key('severity'):
            parsed_msg.errataSeverity = info_match.group('severity')

        return parsed_msg
                
    #Processes an individual mailing list message and returns a messageAnnounce object or none if parsing failed
    #Really bad parsing errors lead to an exception
    def processMessage(self,message_text):        
        try:
            errataMsg = email.message_from_string(message_text)
            stripNewLine = re.compile('\n')

            erratum_subject = errataMsg.get("Subject")
            if erratum_subject is None:
                return None
            
            erratum_subject = stripNewLine.sub("",erratum_subject)
            
            parsed_msg=self.processMessageSubject(erratum_subject)

            if parsed_msg is None:
                return None

            parsed_msg.errataDate = errataMsg.get("Date")
            parsed_msg.packageByArch = self.processPackageList(errataMsg.get_payload())
                    
            return parsed_msg
        except Exception, e:
            print "Failed to process message. Reason:"
            print e
            traceback.print_exc(file=sys.stdout)

        return None 
        
    
    #Performs parsing on the specified errata source. What this
    #actually means will vary between the different parsers
    #Will return list of MessageAnnounce objects, or throw an exception
    def parse(self):
        raise NotImplementedError("This method is implemented in subclasses, you should not call it from MessageParser")

class ParseError(Exception):
    def __init__(self, value):
        self.value = value
        
    def __str__(self):
        return repr(self.value)

class MessageDigest(MessageParser):

    DIGEST_BEGIN="----------------------------------------------------------------------\n\n"
    DIGEST_SEPARATOR="------------------------------\n\n"
    
    def __init__(self,options,input_file):
        MessageParser.__init__(self,options)
        self.inputFile=input_file

    
    def parse(self):
        inputData=open(self.inputFile).read()
        digestMsg=email.message_from_string(inputData)
        
        if digestMsg.is_multipart():
            raise ParseError("Don't know how to handle multipart messages")

        try:
            digestPayloads = digestMsg.get_payload().split(MessageDigest.DIGEST_BEGIN)[1]
            messages = digestPayloads.split(MessageDigest.DIGEST_SEPARATOR)
        except IndexError,index_msg:
            raise ParseError("The file %s does not appear to be a digest from centos-announce" % self.input_file)

        self.parsedMessages=list()
        
        for msg in messages:
            processed = self.processMessage(msg)
            if processed is not None:
                self.parsedMessages.append(processed)
            
        return self.parsedMessages

class MessageArchiveFile(MessageParser):

    #Split on lines formatted thusly: From kbsingh at centos.org  Thu Jan  8 16:25:09 2009       
    ARCHIVE_SEPARATOR="From .*[A-Za-z]{3,3} [A-Za-z]{3,3} [ 0-9]{2,2} \d{2,2}:\d{2,2}:\d{2,2} \d{4,4}\n"
    splitter_re = re.compile(ARCHIVE_SEPARATOR)
    
    def __init__(self,options,input_file):
        MessageParser.__init__(self,options)
        self.inputFile=input_file

    def parse(self):
        inputData=open(self.inputFile).read()

        self.parsedMessages=list()
        
        for msg in MessageArchiveFile.splitter_re.split(inputData):
            processed = self.processMessage(msg)
            if processed is not None:
                self.parsedMessages.append(processed)
    
        return self.parsedMessages

class MessageMailArchive(MessageParser):

    #Where we pull mailarchive messages from
    MAILARCHIVE_BASE="http://www.mail-archive.com/centos-announce@centos.org/"

    #Things to match in pages downloaded from mail-archive.com
    MAILARCHIVE_SUBJECT = "<span class=\"subject\"><a name=\"(?P<msgid>\d+)\" href=\"(?P<relurl>[\w.]+)\">(?P<subject>\[[^]]*\]\s+[^<]+)</a></span>"
    MAILARCHIVE_DATE = "<span class=\"date\">(?P<datestr>[^<]*)</span>"
    
    subjects_re = re.compile(MAILARCHIVE_SUBJECT)
    dates_re = re.compile(MAILARCHIVE_DATE)

    #TODO We should really use an SGML parser instead of doing this...
    body_start_re = re.compile("<pre>")
    body_end_re = re.compile("</pre>")
    checksum_re = re.compile("(?P<checksum>\S{64,})")
    rpm_file_re = re.compile("(?P<pkg_filename>[\.\w-]+.rpm)")
    clean_subject_re = re.compile("<[^>]*>")
    
    def __init__(self,options):
        MessageParser.__init__(self,options)

    def processMailArchiveMessage(self,parsed_msg,msg_url):
        
        try:
            print "Downloading errata data from %s " % msg_url                                    
            message_f = urllib.urlopen(msg_url)
            message_src = message_f.read()
            message_f.close()                                  

            dates_match = MessageMailArchive.dates_re.search(message_src,re.MULTILINE)
            
            if not dates_match is None:
                parsed_msg.errataDate=dates_match.group('datestr')

            #Process the message body into a form acceptable to processPackageList as mailarchive helpfully puts checksum & package on 2 lines...
            message_body=""
            accumulate=False
            current_checksum=None
            current_rpm=None
            for line in message_src.split("\n"):
                if MessageMailArchive.body_start_re.match(line):
                    accumulate=True

                if MessageMailArchive.body_end_re.match(line):
                    accumulate=False

                if accumulate:
                    checksum_match = MessageMailArchive.checksum_re.match(line)
                    rpm_match = MessageMailArchive.rpm_file_re.match(line)

                    if checksum_match is not None:
                        current_checksum = checksum_match.group('checksum')

                    if rpm_match is not None:
                        current_rpm = rpm_match.group('pkg_filename')

                    if current_checksum is not None and current_rpm is not None:
                        message_body+="%s %s\n" % (current_checksum,current_rpm)
                        current_checksum=None
                        current_rpm=None
                    elif checksum_match is None and rpm_match is None:
                        message_body+=line+"\n"                        
            
            parsed_msg.packageByArch = self.processPackageList(message_body)

            return parsed_msg
        except Exception, e:
            print "Failed to process message. Reason: %s" % e
            traceback.print_exc(file=sys.stdout)
            
        return None        
                            
    def parse(self):

        #in test mode we use our predownloaded test data
        if self.options.testmode:
            mailarchive_url="file://%s/testdata/mailarchive/" % (os.path.abspath(  os.path.dirname(sys.argv[0])+"/" ))
            print "Using test data at %s " % mailarchive_url
        else:
            mailarchive_url=MessageMailArchive.MAILARCHIVE_BASE
        
        try:
            messages_list_f = urllib.urlopen(mailarchive_url+"maillist.html")
            s = messages_list_f.read()
            messages_list_f.close()       
        except IOError,e:
            raise ParseError("Failed to open URL %s. Reason: %s" % (mailarchive_url+"maillist.html",e))

        self.parsedMessages = list()
        
        lines = s.split("\n")
    
        for line in lines:
            subjects_match = MessageMailArchive.subjects_re.match(line)

            if len(self.parsedMessages) >= self.options.max_errata:
                print "Max errata count %d exceeded. Processing no more errata" % self.options.max_errata
                return self.parsedMessages

            if subjects_match is None:
                continue

            msg_subject = subjects_match.group('subject')
            msg_subject = MessageMailArchive.clean_subject_re.sub("",msg_subject)
            
            parsed_msg = self.processMessageSubject(msg_subject)

            if parsed_msg is None:
                print "Failed to process subject %s " % msg_subject
                continue
            
            msg_url=mailarchive_url+subjects_match.group('relurl')
            
            parsed_msg_full = self.processMailArchiveMessage(parsed_msg,msg_url)
            if parsed_msg_full is not None:
                self.parsedMessages.append(parsed_msg_full)
              
        return self.parsedMessages

class SearchStrategy(object):

    def __init__(self,config):
        self.config=config
    
    def findPackage(self,erratum,pkg_name,pkg_checksum):
        raise NotImplementedError("This is implemented in our subclasses")
    
    def getName(self):
        return "BASECLASS DO NOT USE"


    #Swiped from http://www.sharms.org/blog/2009/05/21/python-rpm/ as rpm-python has no documentation
    @staticmethod
    def processRPMFile(pkgfile):        
        rpmQuery = rpm.ts()
        try:
            fd = os.open(pkgfile, os.O_RDONLY)
            header = rpmQuery.hdrFromFdno(fd)
            os.close(fd)
        except Exception,msg:
            print "process_pkg_file failed with exception %s. " % msg
            traceback.print_exc(file=sys.stdout)
            return None

        pkgInfo = RHNPackage(header['name'],header['version'],header['release'],header['epoch'],header['arch'])

        return pkgInfo

class SearchDir(SearchStrategy):

    def __init__(self,config):
        SearchStrategy.__init__(self,config)
    
    def findPackage(self,erratum,erratum_arch,pkg_info):

        if erratum.x_isFastTrack:                
            package_dir = self.config.get_fasttrack_package_dir(erratum_arch)
        else:
            package_dir = self.config.get_package_dir(erratum_arch)

        #TODO: could compare checksums here
        rpm_pkg_info = SearchStrategy.processRPMFile(package_dir+pkg_info.filename)
        if rpm_pkg_info is None:
            print "Warning: package %s%s does not exist or cannot be read." % (package_dir,pkg_info.filename)

        return rpm_pkg_info
    
    def getName(self):
        return "dir"

class SearchSpacewalk(SearchStrategy):

    PACKAGE_NAMEONLY="(?P<pkg_name>.*?)-\d+.([\.\w-]+.rpm)"

    package_name_re=re.compile(PACKAGE_NAMEONLY)
    
    def __init__(self,config,session):
        SearchStrategy.__init__(self,config)
        self.rhnSession=session

    def findPackage(self,erratum,erratum_arch,pkg_info):
        pkg_name_match = SearchSpacewalk.package_name_re.match(pkg_info.filename)
    
        if pkg_name_match is None:
            print "Bad package filename %s" % pkg_info.filename
            return None

        pkg_name_only = pkg_name_match.group('pkg_name')

        print "Searching for "+pkg_name_only+" "+pkg_info.checksum
        if self.rhnSession is None:
            print "Test mode: would search spacewalk for %s (%s)" % (pkg_name_only, pkg_info.checksum)
            return None
    
        return self.rhnSession.findPackageByNameAndChecksum(pkg_name_only, pkg_info.checksum)        

    def getName(self):
        return "spacewalk"

class SearchFederated(SearchStrategy):

    def __init__(self,config,session,strategies):
        SearchStrategy.__init__(self,config)
        
        self.rhnSession = session
        self.strategies = list()
        for strategy_name in strategies:
            if strategy_name=='dir':
                self.strategies.append(SearchDir(config))
            elif strategy_name=='spacewalk':
                self.strategies.append(SearchSpacewalk(config,session))
            elif strategy_name=='satellitedir':
                self.strategies.append(SearchSatelliteDir(config))
            else:
                raise "Unknown search strategy %s " % strategy_name

    #Find the packages in all our configured search strategies
    def findPackage(self,erratum,pkg_name,pkg_checksum):
        pkg_info=None
        
        for strategy in self.strategies:            
            pkg_info = strategy.findPackage(erratum,pkg_name,pkg_checksum)

            if pkg_info is not None:
                break
            
            if pkg_info is None and strategy != self.strategies[-1]:
                print "Searching using strategy '%s' failed - trying next strategy" % strategy.getName()

        return pkg_info

class CentOSErrataConfig(object):

    def __init__(self,options,args):
        self.options=options
        self.cmdlineArgs=args

    def get_update_channel(self,target_arch):
        channel_opt = "%s_channel" % target_arch
        if hasattr(self.options,channel_opt):
            return getattr(self.options,channel_opt)
        return None

    def get_package_dir(self,target_arch):
        package_dir_opt = "%s_packagedir" % target_arch
        if hasattr(self.options,package_dir_opt):
            return getattr(self.options,package_dir_opt)
        return None

    def get_fasttrack_update_channel(self,target_arch):
        channel_opt = "%s_fasttrack_channel" % target_arch
        if hasattr(self.options,channel_opt):
            return getattr(self.options,channel_opt)
        return None

    def get_fasttrack_package_dir(self,target_arch):
        package_dir_opt = "%s_fasttrack_packagedir" % target_arch
        if hasattr(self.options,package_dir_opt):
            return getattr(self.options,package_dir_opt)
        return None

#Config constants. 
CONFIG_FILE="centos-errata.cfg"
VALID_ARCH=set(["i386","x86_64","ia64","ppc", "alpha", "sparc", "s390", "s390(x)"])

#Things to match in pages downloaded from RHN
RHN_ERRATA_DETAILS="<h2>Details</h2>(\s+)<div class=\"page-summary\">(?P<details>[\w\W\s]+)</div>(\s+)<br />(\s+)<h2>Solution</h2>"
RHN_ERRATA_SOLUTION="<h2>Solution</h2>(\s+)<div class=\"page-summary\">(?P<solution>[\w\W\s]+)</div>(\s+)<br />(\s+)<h2>Updated packages</h2>"
    
#Cache of already processed errata
errata_cache = ErrataCache()
active_arches = []

def process_args():

    config = ConfigParser.SafeConfigParser()
    try:
        #Could add a search path for this config file
        config.readfp(open(CONFIG_FILE))
    except IOError,err:
        print "Unable to read default config file %s. This file is required for correct operation of the tool. \mReason: %s" % (CONFIG_FILE,err)
        sys.exit(1)
    
    parser = OptionParser(usage="%prog [options] [filename]",version="%prog 0.7")
    RHNSession.addRequiredOptions(parser)

    parser.add_option("","--max-errata",type="int",dest="max_errata",default=10000,
                      help="Maximum number of errata to process at once. Only relevant to format 'mail-archive.com'")
    parser.add_option("-c","--config",type="string",dest="config_file",
                      help="Read the specified config file in addition to the default %s" % CONFIG_FILE)
    parser.add_option("-f","--format",type="string",dest="format",default="digest",
                      help="Select input format for tool. Default is digest. Valid options are digest, archive, mail-archive.com")
    parser.add_option("","--scrape-rhn",action="store_true",dest="scrape_rhn",default=False,
                      help="Connect to the RedHat Network site and attempt to download errata information")
    parser.add_option("","--satellite-dir",type="string",dest="satellite_dir",default="/var/satellite",
                      help="If running on a spacewalk server, specify the location of RPM files (default: /var/satellite)")
    parser.add_option("","--show-config",action="store_true",dest="print_config", default=False,
                      help="Do not connect to the Spacewalk server, just print configuration information")
    parser.add_option("-t","--test",action="store_true",dest="testmode", default=False,
                      help="Do not connect to the Spacewalk server, just process the input file and print errata information. Will also print configuration information")
    parser.add_option("","--centos-version",type="string",dest="centos_version",
                      help="The centos version (e.g. '5' for Centos 5.3) ")
    parser.add_option("","--search-strategies",type="string",dest="search_strategies",
                      help="Set place(s) to look for package NVREA. The only allowable search strategy is \"dir\" (look in the package directories). Example: \"dir\"")

    #Have to perform DIRTY HACK here because optparse will exit early
    #if -h is passed, not what we want since we only want to retrieve
    #the config file at this point and parse again later. The ideal
    #would be the ability to prevent parse_args from exiting early so
    #we could call it twice even with --help

    user_config = None
    try:
        arg_index = sys.argv.index("-c")
        user_config = sys.argv[arg_index+1]                
    except Exception,err:
        pass
    
    if not user_config is None:
        user_cfg_result = config.read([user_config])
        if len(user_cfg_result) != 1 or user_cfg_result[0] != user_config:
            print "Failed to read config file %s " % user_config
            sys.exit(2)
    
    interpolation_vars = {'version' : config.get("centos errata","version"),
                          'release' : config.get("centos errata","release")}
    parser.set_defaults(centos_version=config.get("centos errata","version"))
    parser.set_defaults(centos_release=config.get("centos errata","release"))
    
    
    #Setup args to control our configured architectures
    for arch in VALID_ARCH:        
        if config.has_section(arch):
            active_arches.append(arch)
            channel_label_opt = "%s_channel" % arch
            package_dir_opt = "%s_packagedir" % arch
            fasttrack_channel_label_opt = "%s_fasttrack_channel" % arch
            fasttrack_package_dir_opt = "%s_fasttrack_packagedir" % arch
                        
            parser.add_option("","--%s-channel" % arch ,type="string",dest=channel_label_opt,
                              help="The updates channel for arch %s. Separate multiple channels with a comma" % arch)
            parser.add_option("","--%s-packagedir" % arch ,type="string",dest=package_dir_opt,
                              help="The package directory for arch %s" % arch)
            parser.add_option("","--%s-ft-channel" % arch ,type="string",dest=fasttrack_channel_label_opt,
                              help="The FastTrack updates channel for arch %s. Separate multiple channels with a comma" % arch)
            parser.add_option("","--%s-ft-packagedir" % arch ,type="string",dest=fasttrack_package_dir_opt,
                              help="The FastTrack package directory for arch %s" % arch)
            if config.has_option(arch,"channel"):
                parser.set_default(channel_label_opt,config.get(arch,"channel",0,interpolation_vars))
            if config.has_option(arch,"package_dir"):
                parser.set_default(package_dir_opt,config.get(arch,"package_dir",0,interpolation_vars))                
            if config.has_option(arch,"fasttrack_channel"):
                parser.set_default(fasttrack_channel_label_opt,config.get(arch,"fasttrack_channel",0,interpolation_vars))
            if config.has_option(arch,"fasttrack_package_dir"):
                parser.set_default(fasttrack_package_dir_opt,config.get(arch,"fasttrack_package_dir",0,interpolation_vars))
    
    if config.has_option("spacewalk","server"):
        parser.set_defaults(server=config.get("spacewalk","server"))
    if config.has_option("spacewalk","password"):
        parser.set_defaults(password=config.get("spacewalk","password"))
    if config.has_option("spacewalk","login"):
        parser.set_defaults(login=config.get("spacewalk","login"))
    if config.has_option("spacewalk","satellite_dir"):
        parser.set_defaults(satellite_dir=config.get("spacewalk","satellite_dir"))
    if config.has_option("centos errata","scrape_rhn"):
        parser.set_defaults(scrape_rhn=config.getboolean("centos errata","scrape_rhn"))
    if config.has_option("centos errata", "search_strategies"):
        parser.set_defaults(search_strategies=config.get("centos errata", "search_strategies"))
    if config.has_option("centos errata", "max_errata"):
        parser.set_defaults(max_errata=config.getint("centos errata", "max_errata"))
    
    (options,args) = parser.parse_args()

    return CentOSErrataConfig(options,args)

def download_description(erratum,rhn_url):
     if not erratum.description is None:
         return

     rhn_details_re = re.compile(RHN_ERRATA_DETAILS)
     rhn_solution_re = re.compile(RHN_ERRATA_SOLUTION)
     
     try:
         print "Downloading RHN data for " + erratum.advisoryName
         message_f = urllib.urlopen(rhn_url)
         message_src = message_f.read()
         message_f.close()

         # This causes an error on importing CESA-2011:0927. Try truncating to last 512 bytes or something...
         details_match = rhn_details_re.search(message_src)
         if not details_match is None:
             erratum.description = replace_rhn_content(details_match.group("details"))
             
         solution_match = rhn_solution_re.search(message_src)
         if not solution_match is None:
             erratum.solution = replace_rhn_content(solution_match.group("solution"))
     except:
         print "Failed to download details for %s, using defaults" % erratum.advisoryName
         

def replace_rhn_content(rhn_content):
    try:
        #Hack...
        parsed_xml = lxml.html.fromstring(rhn_content.replace("<br />","\n"))

        #Add in newlines after paragraphs
        for para in parsed_xml.xpath("*//p"):
            para.text = "\n%s\n" % para.text
        
        ret = parsed_xml.text_content()
        ret = ret.replace("Red Hat Enterprise Linux", "CentOS")
    except Exception,err:
        print "Error parsing XML when processing RHN content: %s " % err
        ret = None

    return ret

def prepare_erratum_template(config,cache,msg):
    advisory_name = msg.getAdvisoryName() 
    
    if cache.hasTemplateErrata(advisory_name):
        erratum = cache.templateErrata[advisory_name]
    else:
        erratum = RHNErrata()
            
    erratum.advisoryName = advisory_name
    erratum.publish = True

    #Convert the specifier in messages to that understood by the spacewalk server
    #Default is bug
    if msg.errataType==MessageParser.SECURITY_ERRATA:
        erratum.advisoryType=RHNErrata.SECURITY
    elif msg.errataType==MessageParser.ENHANCE_ERRATA:
        erratum.advisoryType=RHNErrata.ENHANCEMENT
    else:
        erratum.advisoryType=RHNErrata.BUGFIX

    erratum.product = "CentOS "+msg.centosVersion
    erratum.topic=msg.getRHNUrl()

    if config.options.scrape_rhn:
        download_description(erratum,msg.getRHNUrl())

    if erratum.description is None:
        erratum.description =" Automatically imported CentOS erratum"

    if erratum.solution is None:
        erratum.solution = "Install these packages to correct the erratum"

    if msg.errataSeverity is not None:
        erratum.synopsis= msg.errataSeverity+": "+msg.errataSynopsis
    else:
        erratum.synopsis= msg.errataSynopsis

    if msg.errataDate is not None:
        erratum.notes = " Errata announced by CentOS on "+msg.errataDate

    #This is done in the message parsers as well. This is here just-in-case!
    if msg.centosVersion != config.options.centos_version:
         print "Errata '%s' is inapplicable to the targeted CentOS release " % msg.messageSubject
         return None

    cache.addTemplateErrata(erratum)    
    return erratum
    
def prepare_errata(config,pkg_search,cache,msgs):

    for msg in msgs:
        template = prepare_erratum_template(config,cache,msg)

        if template is None:
            continue
        
        errata_count=0
        
        #Iterate and populate errata with packages for each valid architecture
        for template_arch in msg.packageByArch.keys():
            if template.x_isFastTrack:                
                update_channel = config.get_fasttrack_update_channel(template_arch)
            else:
                update_channel = config.get_update_channel(template_arch)
                
            if update_channel is None:
                print "Errata %s: No %s channel configured for architecture '%s'. Skipping this architecture " % (
                    msg.messageSubject,
                    {True: "fasttrack update", False: "update"}[template.x_isFastTrack],
                    template_arch
                    )
                continue

            for unique_channel in update_channel.split(','):
                template.addPublishChannel(unique_channel)

            errata_ok=True
            for msg_pkginfo in msg.packageByArch[template_arch]:
                if msg_pkginfo.filename.endswith(".src.rpm"):
                    continue

                pkg_info = pkg_search.findPackage(template,template_arch,msg_pkginfo)
                
                if pkg_info is not None:
                    template.packages.append(pkg_info)
                else:
                    print "Searching for package %s failed Skipping errata %s" % (msg_pkginfo.filename,template.advisoryName)
                    errata_ok=False
                    break

            if errata_ok:
                cache.addCompleteErrata(template_arch,template)
                errata_count+=0
                                  
        if errata_count == 0:        
            print "Errata '%s' contains no architectures relevant to us. Skipping" % msg.messageSubject
    

def check_input_file(args):
    if len(args) == 0:
        print "I need an input filename. See %s --help" % sys.argv[0]
        sys.exit(2)

    inputFile = args[0]
    if not os.path.exists(inputFile):
        print "Input file %s does not exist" % inputFile
        sys.exit(2)
    elif not os.path.isfile(inputFile):
        print "Input file %s is not a normal file" % inputFile
        sys.exit(2)
    elif not os.access(inputFile,os.R_OK):
        print "Input file %s is not readable" % inputFile
        sys.exit(2)

    return inputFile

def main():
    script_config = process_args()

    if script_config.options.testmode or script_config.options.print_config:
        print "Current configuration:"
        for option,value in script_config.options.__dict__.items():
            print "%-20s = %s" % (option,value)
        if script_config.options.print_config:
            sys.exit(0)  

    abort_test = False
    package_dir_unset = False
    fasttrack_package_dir_unset = False
    for arch in active_arches:
        package_dir = script_config.get_package_dir(arch)        
        fasttrack_package_dir = script_config.get_fasttrack_package_dir(arch)
        fasttrack_package_channel = script_config.get_fasttrack_update_channel(arch)
        
        if package_dir is None:
            print "Warning: %s_packagedir is not set" % arch
            package_dir_unset = True
            continue
        elif not os.path.exists(package_dir):
            print "Warning: %s arch package directory %s does not exist" % (arch,package_dir)
            abort_test = True
        elif not os.path.isdir(package_dir):
            print "Warning: %s arch package dir %s is not a directory" % (arch,package_dir)
            abort_test = True
        elif not os.access(package_dir,os.R_OK):
            print "Warning: %s arch package dir %s is not readable" % (arch,package_dir)
            abort_test = True

        if not fasttrack_package_channel is None:
            if fasttrack_package_dir is None:
                print "Warning: %s_fasttrack_packagedir is not set" % arch
                fasttrack_package_dir_unset = True
                continue
            elif not os.path.exists(fasttrack_package_dir):
                print "Warning: %s arch fasttrack package directory %s does not exist" % (arch,fasttrack_package_dir)
                abort_test = True
            elif not os.path.isdir(fasttrack_package_dir):
                print "Warning: %s arch fasttrack package dir %s is not a directory" % (arch,fasttrack_package_dir)
                abort_test = True
            elif not os.access(fasttrack_package_dir,os.R_OK):
                print "Warning: %s arch fasttrack package dir %s is not readable" % (arch,fasttrack_package_dir)
                abort_test = True
            
    if abort_test and script_config.options.testmode:
        print "Test mode does not access the spacewalk server and therefore requires package directories"
        sys.exit(2)

    search_strategies = map((lambda strat: strat.strip().lower()),script_config.options.search_strategies.split(","))
    strategy_ok = True
    for strategy in search_strategies:
        if strategy == "dir":
            if package_dir_unset:
                print "You cannot use the 'dir' search strategy without specifying package directories for each architecture"
                strategy_ok = False
            if fasttrack_package_dir_unset:
                print "You cannot use the 'dir' search strategy without specifying fasttrack package directories for each architecture with a fasttrack channel enabled"
                strategy_ok = False
                
        elif strategy == "spacewalk":
            if script_config.options.testmode:
                print "Warning: you are using test mode and have the spacewalk search strategy enabled.\nThis will return no results as there is no connection to the spacewalk server in test mode"
            print "The satellite strategy no longer works due to CentOS sending out sha256 signatures instead of md5sum signatures. Use 'dir'"    
            strategy_ok = False
        elif strategy == "satellitedir":
            if not os.path.exists(script_config.options.satellite_dir):
                print "Warning: satellite dir %s does not exist. You need to be running this on a spacewalk server" % script_config.options.satellite_dir
            print "The satellitedir strategy no longer works due to CentOS sending out sha256 signatures instead of md5sum signatures. Use 'dir'"    
            strategy_ok = False
        else:
            print "Invalid search strategy '%s'. " % strategy
            strategy_ok = False

    if not strategy_ok:
        print "Correct invalid search strategies before proceeding. See %s --help" % sys.argv[0]
        sys.exit(2)
    
    if script_config.options.format == "mail-archive.com":         
        message_parser=MessageMailArchive(script_config.options)
    elif script_config.options.format == "archive": 
        inputFile=check_input_file(script_config.cmdlineArgs)
        message_parser=MessageArchiveFile(script_config.options,inputFile)
    elif script_config.options.format == "digest":
        inputFile=check_input_file(script_config.cmdlineArgs)
        message_parser=MessageDigest(script_config.options,inputFile)                    
    elif not script_config.options.format is None:
        print "Unknown format %s. See --help for valid formats " % script_config.options.format
        sys.exit(2)

    session = None
    if not script_config.options.testmode:
        session = RHNSession.establishSession(script_config.options,sys.argv[0])

    pkg_search=SearchFederated(script_config,session,search_strategies)

    try:
        parsed_messages=message_parser.parse()
    except Exception,e:
        print "Failed to parse messages due to exception %s" % e
        traceback.print_exc(file=sys.stdout)
        sys.exit(2)
        
    if len(parsed_messages) > 0:
        prepare_errata(script_config,pkg_search,errata_cache,parsed_messages)
    else:
        print "No errata found in any of the mailing list messages"
        sys.exit(0)

    #Process any errata we have
    for arch in errata_cache.getActiveArchitectures():
        errata_for_arch=errata_cache.getCompleteErrata(arch)
        errata_count = len(errata_for_arch.keys())
        
        if errata_count == 0:
            continue

        print "Arch %s: Processing %d errata..." % (arch,errata_count)

        for erratum in errata_for_arch.values():
            try:
                if script_config.options.testmode:
                    print "In test mode. Not checking server for existing erratum %s" % erratum.advisoryName
                    erratum.printOut()
                    print "------"
                else:
                    skip = False
                    if not session.getErrataDetails(erratum.advisoryName) is None:
                        print "Errata %s already exists on server, skipping" % erratum.advisoryName
                        #If you were going to try updating existing errata, here is where you'd do it
                        #In the 2 years that this script has existed, I've never seen a situation where we'd need to do this though
                        continue

                    for pkg_info in erratum.packages:
                        if pkg_info.id is None:
                            rhn_pkg_info = session.findPackageByNVREA(pkg_info)
                            if not rhn_pkg_info is None:
                                pkg_info.id=rhn_pkg_info.id
                            else:
                                print "Package %s is not available on the server. " % pkg_info.getNVRA() 
                                skip = True

                    if skip:
                        print "Skipping erratum %s due to missing packages" % erratum.advisoryName
                        continue
                    else:
                        session.createErrata(erratum)

            except Exception,e:
                print "An exception occured when communicating with the server. Skipping erratum %s. Reason:" % erratum.advisoryName
                print e
                traceback.print_exc(file=sys.stdout)

    
if __name__ == "__main__":
    main() 
