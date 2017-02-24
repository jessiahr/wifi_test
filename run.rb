require 'securerandom'
require 'timeout'
require 'byebug'
class Probe
  def self.start_mon(ifname = "wlan0")
    puts "starting mon mode"
    monmode_results = `airmon-ng start #{ifname}`

    puts "results: #{monmode_results}"

    #check if the network was put into mon
    if monmode_results.include? "wlan0mon"
      puts "#{ifname} now in mon mode!"
    else
      raise "Network interface: unable to stop"
    end
  end

  def self.stop_mon(ifname = "wlan0")
    puts "stoping mon mode"
    monmode_results = `airmon-ng stop #{ifname}mon`

    puts "results: #{monmode_results}"

    #check if the network was put into mon
    if !monmode_results.include? "wlan0mone"
      puts "SUCCESS"
    else
      raise "Network interface: unable to stop"
    end
  end

  def self.dump
    puts "dumping"
    temp_filename = SecureRandom.hex(10)
    puts "started #{temp_filename}"
    byebug
    status = Timeout::timeout(10) {
      `timeout 10s airodump-ng wlan0mon --essid "~ Camp vibes ~" --output-format "csv" --write-interval 5 -w "./#{temp_filename}" & echo "closing airodump..."`
    } rescue Timeout::Error
    byebug
    File.foreach("#{temp_filename}-01.csv") {|x| print "GOT", x }
  end

  def self.read_dump
    File.foreach("example.csv") do |line|
      print "GOT", line, "{[#{line.split.length}]}"
    end
  end
end
# Probe.read_dump
# Probe.start_mon
# Probe.dump
# Probe.stop_mon
