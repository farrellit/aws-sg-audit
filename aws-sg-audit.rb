#!/usr/bin/env ruby

require_relative "lib/AwsSgAudit.rb"
$log.level =Logger::INFO

asa = AwsSgAudit.new ARGV
unless ARGV.include? '-j'
    asa.loadJson $stdin.read
end
puts asa.parseData 
