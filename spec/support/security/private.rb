Fog::Bouncer.security :private do
  account "jersey_shore", Fog::Bouncer.aws_account_id

  define :ping, "0.0.0.0/0" do
    icmp :echo_request
    icmp :echo_reply
  end

  define :ssh, ["0.0.0.0/0", "1.1.1.1/1"] do
    tcp 22
  end

  define :multiple_sources, "douchebag@jersey_shore" do
    tcp 70
  end

  use :ssh

  group "douchebag", "Don't let them in!" do
    use :ping

    source "1.1.1.1/1" do
      tcp 7070..8080, 80
    end

    source "0.0.0.0/0" do
      icmp :echo_request
      icmp :echo_reply
    end
  end

  group "guido", "Definitely don't let them in!" do
    use :multiple_sources

    source "douchebag@jersey_shore" do
      tcp 7070..8080
      udp 8081
    end

    source "other@#{Fog::Bouncer.aws_account_id}" do
      icmp :all
    end
  end

  group "other", "Some other randomness" do
    source "douchebag" do
      tcp 80
    end

    source "douchebag" do
      udp 8080
    end
  end
end
