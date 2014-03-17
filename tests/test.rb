require_relative "../lib/AwsSgAudit.rb"

asa = AwsSgAudit.new [ "-j",  "./test.json", "-g", "sg-6fd1cc03", "-p" "8081" ]
puts "\033[1m" + asa.parseData.inspect + "\033[0m"
