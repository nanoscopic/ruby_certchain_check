#!/usr/bin/env ruby

require "openssl"

def verify_cert(cert_file,chain_files)
  
  cert_store = OpenSSL::X509::Store.new
  for chain_file in chain_files
    cert_store.add_file(chain_file)
  end

  verify_error = ''
  
  # setup callback
  cert_store.verify_callback = proc do |preverify_ok, ssl_context|
    begin
      if preverify_ok != true || ssl_context.error != 0
        cert_being_checked = ssl_context.chain[ssl_context.error_depth]
        failed_cert_subject = cert_being_checked.subject
        err_msg = "SSL Verification failed: #{ssl_context.error_string} (#{ssl_context.error}) while verifying #{failed_cert_subject}"
        verify_error += err_msg
        false
      else
        true
      end
    rescue Exception => e
      verify_error += err_msg
      false
    end
  end

  raw = File.read cert_file
  cert = OpenSSL::X509::Certificate.new( raw )

  if cert_store.verify( cert ) == true
    nil
  else
    verify_error
  end
end

chain_files = []
chain_files.push('intermed/root.crt')
chain_files.push('root.crt');

error = verify_cert("intermed/test.com.crt",chain_files);
if error != nil
  puts error
else
  puts "Passed"
end
