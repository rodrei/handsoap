# -*- coding: utf-8 -*-

module Handsoap
  module Http
    module Drivers
      class NetHttpDriver < AbstractDriver
        def self.load!
          require 'net/http'
          require 'uri'
        end

        def send_http_request(request)
          url = request.url
          unless url.kind_of? ::URI::Generic
            url = ::URI.parse(url)
          end
          ::URI::Generic.send(:public, :path_query) # hackety hack
          path = url.path_query
          http_request = case request.http_method
                         when :get
                           Net::HTTP::Get.new(path)
                         when :post
                           Net::HTTP::Post.new(path)
                         when :put
                           Net::HTTP::Put.new(path)
                         when :delete
                           Net::HTTP::Delete.new(path)
                         else
                           raise "Unsupported request method #{request.http_method}"
                         end
                         
          http_client = Net::HTTP.new(url.host, url.port)
          
          #http_client.read_timeout = 120
          http_client.open_timeout = Handsoap.timeout
          http_client.read_timeout = Handsoap.timeout

          http_client.use_ssl = true if url.scheme == 'https'

          if request.username && request.password
            # TODO: http://codesnippets.joyent.com/posts/show/1075
            http_request.basic_auth request.username, request.password
          end
          request.headers.each do |k, values|
            values.each do |v|
              http_request.add_field(k, v)
            end
          end
          http_request.body = request.body
          # require 'stringio'
          # debug_output = StringIO.new
          # http_client.set_debug_output debug_output
          http_response = http_client.start do |client|
            response = client.request(http_request)
          end
          #raise http_response.each_header.map {|o|[o, http_response.header[o]]}.inspect


          # Try NTLM Authentication
          if request.username && request.password
            if http_response.code.to_i == 401 and http_response.header['www-authenticate'].include?("NTLM")
              http_response = send_http_request_with_ntlm_auth(:client => http_client,
                                                               :request => http_request,
                                                               :username => request.username,
                                                               :password => request.password)
            end
          end

          # puts debug_output.string
          # hacky-wacky
          def http_response.get_headers
            @header.inject({}) do |h, (k, v)|
              h[k.downcase] = v
              h
            end
          end

          # net/http only supports basic auth. We raise a warning if the server requires something else.
          auth_types = http_response.get_headers['www-authenticate'].map(&:downcase)
          if http_response.code.to_i == 401 && auth_types.any?
            unless auth_types.include?("basic") || auth_types.include?("ntlm")
              raise "Authentication types #{auth_types.join(",")} are unsupported by net/http"
            end
          end
          parse_http_part(http_response.get_headers, http_response.body, http_response.code)
        end

        def send_http_request_with_ntlm_auth(options)
          client = options[:client]
          request = options[:request]
          username = options[:username]
          password = options[:password]

          client.start do |http|
            # Message 1 Client -> Server
            t1 = Net::NTLM::Message::Type1.new()
            request['Authorization'] = 'NTLM ' + t1.encode64
            response = http.request(request)
            #debug_response(response)

            # Message 2 Server -> Client
            if /\A(NTLM|Negotiate) (.+)\z/ =~ response.header['www-authenticate']
              msg = $2
            else
              raise "NTML authentication error: Message 2 has unexpected format"
            end

            # Message 3 Client -> Server
            t2 = Net::NTLM::Message.decode64(msg)
            t3 = t2.response({:user => username, :password => password}, {:ntlmv2 => true})

            request['Authorization'] = 'NTLM ' + t3.encode64
            response = http.request(request)
            #debug_response(response)
            response
          end
        end

        #def debug_response(response)
        #  puts response.msg
        #  response.header.each_header do |h| puts h.inspect + "  " + response.header[h] end
        #end
      end
    end
  end
end
