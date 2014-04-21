module Fog
  module Bouncer
    class Protocol
      attr_reader :from, :local, :source, :to
      attr_writer :local, :remote

      def self.range(port)
        if port.is_a?(Range)
          [port.begin, port.end]
        else
          [port, port]
        end
      end

      def initialize(port, source)
        @from, @to = Protocol.range(port)
        @source = source
        validate
      end

      def group
        source.group
      end

      def local
        @local ||= false
      end

      def local?
        !!local
      end

      def match(type, port)
        type.to_s == self.type && Protocol.range(port) == [from, to]
      end

      def remote
        @remote ||= false
      end

      def remote?
        !!remote
      end

      def type
        @type ||= self.class.to_s.gsub("Fog::Bouncer::Protocols::", "").downcase
      end

      def ==(other)
        type == other.type &&
        from == other.from &&
        to == other.to
      end

      def <=>(other)
        [from, to] <=> [other.from, other.to]
      end

      def inspect
        "<#{self.class.name} @from=#{from.inspect} @to=#{to.inspect} @local=#{local} @remote=#{remote}>"
      end

      def to_log
        { source: source.source, protocol: type, from: from, to: to }
      end
    end

    module Protocols
      class InvalidICMPType < StandardError; end
      class InvalidPort < StandardError; end

      class ICMP < Protocol
        ICMP_MAPPING = {
          all: -1,
          ping: 0..8
        }

        ICMP_TYPE_RANGE = (-1..255)

        def initialize(port, source)
          if port.is_a?(Symbol) && range = ICMP_MAPPING[port]
            port = range
          end
          super
        end

        def match(type, port)
          if port.is_a?(Symbol) && range = ICMP_MAPPING[port]
            type.to_s == self.type && Protocol.range(range) == [from, to]
          else
            super
          end
        end

        private

        def validate
          raise InvalidICMPType.new("Must be between and including -1 and 255.") unless ICMP_TYPE_RANGE.include?(from)
        end
      end

      class TCP < Protocol
        private

        def validate
          raise InvalidPort.new("Invalid port #{from}. Must be between and including 0 and 65535.") unless (0..65535).include?(from)
        end
      end

      class UDP < Protocol
        private

        def validate
          raise InvalidPort.new("Invalid port #{from}. Must be between and including 0 and 65535.") unless (0..65535).include?(from)
        end
      end
    end
  end
end
