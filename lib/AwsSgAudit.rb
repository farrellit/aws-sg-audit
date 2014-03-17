require 'json'
require 'logger'
require 'optparse'

$log = Logger.new $stderr 
$log.level = Logger::DEBUG

class AwsSgAudit 
    
    def self.defaultOptions 
        {
            :ports  => [],
            :cidrs  => [],
            :groups => [],
            :json => nil
        }
    end
    
    def self.parseOptions( args, options = nil)
        options = self.defaultOptions unless options
        OptionParser.new do |opts|
            opts.banner = "Usage: #{$0} [ filters ]"
            opts.on "-p", "--port PORT", Integer, "Filter out rules for PORT" do |port|
                options[ :ports ] << port
            end
            opts.on "-c", "--cidr CIDR", "Filter out rules for CIDR block" do |cidr|
                options[ :cidrs ] << cidr
            end
            opts.on "-g", "--group SECURITYGROUP", "Filter out rules for SECURIRYGROUP" do |group|
                options[ :groups ] << group
            end
            opts.on "-j", "--json JSONDATA", "Provide JSON filename" do |json|
                options[ :json ] = json
            end
        end.parse! args
        options
    end
 
    def initialize opts=[]
        @data = nil
        @results = []
        configure( opts )
    end

    def configure opts 
        unless opts.kind_of? Array
            raise InputError.new "#{self.class.name}##{__method__} expects an Array, but received #{opts.class.name} "
        end
        @options = self.class.parseOptions opts, @options
        loadJson(File.read @options[:json]) if @options[:json] 
    end

    def loadJson( json )
        begin 
            @data = JSON.parse json
        rescue JSON::ParserError => e
            raise InputError.new "Could not read JSON data from standard input - #{e.class.name}: #{e.message}"
        end
        @results = [] 
    end

    def parseData
        @results = [] 
        sgs = @data['SecurityGroups'] 
        unless sgs.kind_of? Array
            raise InputError.new "Couldn't find section 'SecurityGroups' at top level of input JSON"
        end
        sgs.each do |sg|
            unless @options[:groups].count == 0 or 
                @options[:groups].include? sg['GroupId']
                $log.debug "Security group #{sg['GroupId']} does not match specified groups; skipping"
                next
            end
            $log.debug "Examining Security Group #{sg['GroupId']} : #{sg['GroupName']}"
            ip_permissions = sg['IpPermissions']
            unless ip_permissions.kind_of? Array
                raise InputError.new "Couldn't find 'IpPermissions' array under SecurityGroups'"
            end
            ip_permissions.each_index do |index|
                cidr_matches = []
                ip_permission = ip_permissions[index]
                if @options[:ports].count > 0
                    $log.debug "Examining IP Permission ##{index} "+ 
                        "Port Range #{ip_permission['FromPort']}-#{ip_permission['ToPort']}"
                    next unless doPortsMatch? ip_permission
                end
                if @options[:cidrs].count > 0 
                    $log.debug "Examinig IP Permission3 ##{index} Cidr Blocks"
                    cidr_matches = doCidrsMatch? ip_permission
                    $log.debug "These Cidr Block(s) match: #{cidr_matches.inspect}"
                    next unless cidr_matches.length > 0
                else
                    cidr_matches = ip_permission['IpRanges'].map { |range| range['CidrIp'] }               
                end
                $log.debug "IP Permissions match: #{ ip_permission.to_json }"
                @results << { 
                    "Group" => sg['GroupId'],
                    "FromPort" => ip_permission['FromPort'] , 
                    "ToPort" => ip_permission['ToPort'] , 
                    "CidrIp" => cidr_matches
                }
            end
        end 
        @results
    end


    def doPortsMatch? ip_permission
        fromPort = ip_permission['FromPort']
        toPort = ip_permission['ToPort']
        return false unless fromPort and toPort 
        @options[:ports].select { |p|
            return true if p >= fromPort and p <= toPort 
        }
        false
    end

    def doCidrsMatch? ip_permission
        matches = []
        ip_permission['IpRanges'].each do |range|
            matches << range['CidrIp'] if @options[:cidrs].include? range['CidrIp']
        end
        matches  
    end

    ## Exceptions
    class AwsSgAuditError < Exception; end
    class InputError < AwsSgAuditError; end


end

