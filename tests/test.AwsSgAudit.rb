
require "../lib/AwsSgAudit.rb"

describe AwsSgAudit do
    
    it "should provide expected default options" do
        AwsSgAudit.defaultOptions.should == { :ports => [], :cidrs => [], :groups => [], :json => nil }
    end

    it "should parse empty options and return default" do
        AwsSgAudit.parseOptions( [] ).should == AwsSgAudit.defaultOptions
    end

    it "should accept one port setting" do
        AwsSgAudit.parseOptions( 
            [ "-p", "22" ] 
        ).should  == { :ports=>[22],:cidrs=>[],:groups=>[], :json => nil }
        AwsSgAudit.parseOptions( 
            [ "--port", "3306" ] 
        ).should  == { :ports=>[3306],:cidrs=>[],:groups=>[], :json => nil }
    end
    it "should accept multiple port settings" do
        AwsSgAudit.parseOptions( 
            [ "-p", "22", "-p", "3306", "-p", "55672" ] 
        ).should  == { :ports=>[22,3306,55672],:cidrs=>[],:groups=>[] , :json => nil}
        AwsSgAudit.parseOptions( 
            [ "--port", "22", "--port", "3306", "--port", "55672" ] 
        ).should  == { :ports=>[22,3306,55672],:cidrs=>[],:groups=>[], :json => nil }
    end

    it "should accept one group setting" do
        AwsSgAudit.parseOptions( 
            [ "-g", "group1" ] 
        ).should  == { :ports=>[],:cidrs=>[],:groups=>["group1"], :json => nil }
        AwsSgAudit.parseOptions( 
            [ "--group", "group1" ] 
        ).should  == { :ports=>[],:cidrs=>[],:groups=>["group1"], :json => nil }
    end
    it "should accept multiple group settings" do
        AwsSgAudit.parseOptions( 
            [ "-g", "group1", "-g", "group2", "-g", "group3" ] 
        ).should  == { :ports=>[],:groups=>["group1","group2","group3"],:cidrs=>[], :json => nil }
        AwsSgAudit.parseOptions( 
            [ "--group", "group1", "--group", "group2", "--group", "group3" ] 
        ).should  == { :ports=>[],:groups=>["group1","group2","group3"],:cidrs=>[], :json => nil }
    end

    it "should accept one cidr setting" do
        AwsSgAudit.parseOptions( 
            [ "-c", "192.168.0.0/16" ] 
        ).should  == { :ports=>[],:cidrs=>["192.168.0.0/16"],:groups=>[], :json => nil }
        AwsSgAudit.parseOptions( 
            [ "--cidr", "192.168.0.0/16" ] 
        ).should  == { :ports=>[],:cidrs=>["192.168.0.0/16"],:groups=>[], :json => nil }
    end
    it "should accept multiple cidr settings" do
        AwsSgAudit.parseOptions( 
            [ "-c", "10.0.0.0/8", "-c", "172.12.0.0/16", "-c", "192.168.70.1/32" ] 
        ).should  == { :ports=>[],:cidrs=>["10.0.0.0/8","172.12.0.0/16","192.168.70.1/32"],:groups=>[], :json => nil }
        AwsSgAudit.parseOptions( 
            [ "--cidr", "10.0.0.0/8", "--cidr", "172.12.0.0/16", "--cidr", "192.168.70.1/32" ] 
        ).should  == { :ports=>[],:cidrs=>["10.0.0.0/8","172.12.0.0/16","192.168.70.1/32"],:groups=>[], :json => nil }
    end
    
    it "should accept a -j option" do
        AwsSgAudit.parseOptions( 
            [ "-j", "{ json }" ]
        ).should  == { :ports=>[],:cidrs=>[],:groups=>[], :json => "{ json }" }
        AwsSgAudit.parseOptions( 
            [ "--json", "{ json }" ]
        ).should  == { :ports=>[],:cidrs=>[],:groups=>[], :json => "{ json }" }
    end

    it "should use the last -j option" do
        AwsSgAudit.parseOptions( 
            [ "-j", "{ json }", "--json", "{ more json }" ]
        ).should  == { :ports=>[],:cidrs=>[],:groups=>[], :json => "{ more json }" }
    end

    opts = nil
    it "should accept all options together" do
        AwsSgAudit.parseOptions( 
            opts = [ 
                "-c", "10.0.0.0/8", "-c", "172.12.0.0/16", "-c", "192.168.70.1/32" ,
                "-g", "group1", "-g", "group2", "-g", "group3",
                "-p", "22", "-p", "3306", "-p", "55672", 
                "--json", "{ a blob of ostensibly json }"
            ] 
        ).should  == { 
            :ports=>[22,3306,55672],
            :cidrs=>["10.0.0.0/8","172.12.0.0/16","192.168.70.1/32"],
            :groups=>["group1","group2","group3"],
            :json => "{ a blob of ostensibly json }"
        }
    end
 
    it "Should initialize cleanly with no arguments" do
        AwsSgAudit.new
    end

    it "Should initialize cleanly with valid arguments" do
        AwsSgAudit.new opts
    end

    it "Should raise an AwsSgAudit::InputError if initialized with a non-array" do
        expect { 
            AwsSgAudit.new "this is not an array"
        }.to raise_error AwsSgAudit::InputError 
    end
    it "Should raise something if initialized with invalid options" do
        expect { 
            AwsSgAudit.new [ "--badoption", "4" ]
        }.to raise_error OptionParser::InvalidOption

    end

    it "should raise AwsSgAudit::InputError on loadJson with invalid json" do
        expect { 
            AwsSgAudit.new.loadJson( "{ invalid json }" )
        }.to raise_error AwsSgAudit::InputError 
    end

    it "should identify appropriate matching ports" do
        asa = AwsSgAudit.new [ "-p", "22" ]
        asa.doPortsMatch?( 
            { 'FromPort'=>22,'ToPort'=>22 } 
        ).should == true
        asa.doPortsMatch?( 
            { 'FromPort'=>0,'ToPort'=>65535 } 
        ).should == true
        asa.doPortsMatch?( 
            { 'FromPort'=>22,'ToPort'=>65535 } 
        ).should == true
        asa.doPortsMatch?( 
            { 'FromPort'=>0,'ToPort'=>22} 
        ).should == true

        asa.doPortsMatch?( 
            { 'FromPort'=>23,'ToPort'=>65535 } 
        ).should == false
        asa.doPortsMatch?( 
            { 'FromPort'=>0,'ToPort'=>21} 
        ).should == false

    end


    it "should identify matching CIDR blocks" do 
        asa = AwsSgAudit.new [ "-c", "127.0.0.1/32" ]
        asa.doCidrsMatch?( 
            { 'IpRanges' => [ { 'CidrIp' => '127.0.0.1/32' }, { 'CidrIp' => '192.168.70.0/24'} ] }
        ).should == [ "127.0.0.1/32" ] 
        asa = AwsSgAudit.new [ "-c", "192.168.70.0/24" ]
        asa.doCidrsMatch?( 
            { 'IpRanges' => [ { 'CidrIp' => '127.0.0.1/32' }, { 'CidrIp' => '192.168.70.0/24'} ] }
        ).should == [ "192.168.70.0/24" ]
        asa = AwsSgAudit.new [ "-c", "127.0.0.1/32", "-c", "192.168.70.0/24" ]
        asa.doCidrsMatch?( 
            { 'IpRanges' => [ { 'CidrIp' => '127.0.0.1/32' }, { 'CidrIp' => '192.168.70.0/24'} ] }
        ).should == [ "127.0.0.1/32", "192.168.70.0/24" ] 
        asa = AwsSgAudit.new [ "-c", "10.0.0.0/8" ]
        asa.doCidrsMatch?( 
            { 'IpRanges' => [ { 'CidrIp' => '127.0.0.1/32' }, { 'CidrIp' => '192.168.70.0/24'} ] }
        ).should == []
    end

    it "should parse valid json" do 
        asa = AwsSgAudit.new [ "-j",  "./test.json", "-g", "sg-abcdef01", "-p" "8081", "-c", "192.168.146.0/24" ]
        asa.parseData.should == [ { 
            'Group' => "sg-abcdef01", 
            "FromPort"=> 8081, "ToPort" => 8081, 
            "CidrIp" => [ "192.168.146.0/24" ] 
        } ]
    end

end
