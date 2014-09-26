require 'openssl'
require 'rack'

module Rack
  class ClientCerts

    def self.ca_file(ca_file)
      @@ca_file = ca_file
    end

    def initialize(app)
      @app = app
      @ca = OpenSSL::X509::Certificate.new( ::File.read( @@ca_file ))
    end

    def call(env)
      if env.has_key? 'rack.peer_cert'
        client_cert = OpenSSL::X509::Certificate.new( env['rack.peer_cert'] )
      elsif env.has_key? 'SSL_CLIENT_CERT' && env['SSL_CLIENT_CERT'].length > 0
        client_cert = OpenSSL::X509::Certificate.new( env['SSL_CLIENT_CERT'] )
      end

      if client_cert && client_cert.issuer == @ca.subject
        res = client_cert.verify(@ca.public_key) ? 'SUCCESS' : 'FAILED'

        if res == 'SUCCESS'
          env["CLIENT-CERT-NAME"]  = extract_name(client_cert)
          env["CLIENT-CERT-EMAIL"] = extract_email(client_cert)
        end

      else
        res = "NONE"
      end

      env["CLIENT-CERT-VERIFY"] = res

      status, headers, body = @app.call(env)

      [status, headers, body]

    end

    private
    def extract_name(cert)
        name_a = cert.subject.to_a.select {|e| e[0] == "CN" }.flatten
        return name_a.nil? ? nil : name_a[1]
    end


    def extract_email(cert)
        email_a = cert.subject.to_a.select {|e| e[0] == "emailAddress" }.flatten
        return email_a.nil? ? nil : email_a[1]
    end
  end
end
