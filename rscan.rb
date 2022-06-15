#!/usr/bin/env ruby

require 'socket'
require 'optimist'
require 'colorize'
require 'timeout'
require 'ipaddr'
require 'threadify'

def arguments
  @opts = Optimist::options do
    version "rscan 0.0.0.1b".light_blue
    banner <<-EOS
      portscanner over proxychains
    EOS

    opt :targethost, "IP Address or CIDR Range", :type => String, :short => "-t"
    opt :port, "Single port, port range (1-100) or comma separated (22,3389,445)", :type => String, :short => "-p"
    opt :hostthreads, "How many hosts do we want to scan simultaneously (determines speed of scan)", :type => Integer, :default => 50, :short => "h"
    opt :portthreads, "How many ports do we want to scan simultaneously (determines speed of scan)", :type => Integer, :default => 8, :short => "-s"


    if ARGV.empty?
      puts "Try ./rscan.rb --help"
      exit
    end
  end
  @opts
end

def parse_scan_addresses
  if @opts[:targethost] =~ /\d+\/\d+/
    @addresses = IPAddr.new(@opts[:targethost]).to_range.to_a.map { |a| a.to_s}
  else
    @addresses = [@opts[:targethost]]
  end
end

def parse_scan_ports
  if @opts[:port] =~ /\d+-\d+/
    @ports = (@opts[:port].split("-")[0]...@opts[:port].split("-")[1])
  elsif @opts[:port] =~ /\d+,\d+/
    @ports = @opts[:port].split(",")
  else
    @ports = [@opts[:port]]
  end
  scanner(@addresses, @ports)
end

def scanner(addresses, ports)
  open_ports = []
  @addresses.threadify(@opts[:hostthreads]) do |address|
    @ports.threadify(@opts[:portthreads]) do |port|
      Timeout.timeout(1) do
        begin
          socket = TCPSocket.new(address, port)
          status = "open"
          open_ports << "#{address} : #{port} : #{status}."
          rescue Errno::ECONNREFUSED, Errno::EACCES
            status = "closed"
          rescue Errno::EHOSTDOWN, Errno::EHOSTUNREACH
            status = "HOST DOWN"
          end
          puts "#{address} : #{port} : #{status}."
        end
      rescue Timeout::Error
        puts "timed out"
    end
  end
  puts "\n:::Open Ports:::\n#{open_ports.join("\r\n")}"
end





arguments
parse_scan_addresses
parse_scan_ports
