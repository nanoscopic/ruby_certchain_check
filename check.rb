#!/usr/bin/env ruby

require "openssl"

def verify_cert_altnames(cert_file,altnames,ip_altnames)
  raw = File.read cert_file
  cert = OpenSSL::X509::Certificate.new( raw )
  #puts get_cert_altnames( cert )
  error = ''
  
  altinfo = get_cert_altnames(cert)
  if altinfo[:error] != 0
    return "Cannot parse altnames from certificate (err=" + altinfo[:error].to_s + ")"
  end
  
  altnames.each do |altname|
    unless altinfo[:altnames].include? altname
      error += altname + "\n"
    end
  end
  
  if error == ''
    nil
  else
    "Certificate is missing the following altnames:\n" + error
  end
end

def get_cert_altnames(cert)
  subject_alt_name = cert.extensions.find { |e| e.oid == "subjectAltName" }
  return { error: 1 } unless subject_alt_name
  #puts "blah"
  asn_san = OpenSSL::ASN1.decode(subject_alt_name)
  asn_san_sequence = OpenSSL::ASN1.decode(asn_san.value[1].value)
  
  # Ruby OpenSSL library does not unfortunately have constants for the DNS altnames versus IP based altnames
  # See verify_certificate_identity in https://github.com/ruby/openssl/blob/master/lib/openssl/ssl.rb
  
  # There are actually 9 types, as defined by RFC5280 ( https://tools.ietf.org/html/rfc5280#section-4.2.1.6 )
  # DNS string hostnames are type 2 ( dNSName )
  # Both ipv4 and ipv6 addresses are type 7 ( iPAddress )
  # Email addresses are stored as type 1 ( rfc822Name )
  
  altnames = []
  ip_altnames = []
  asn_san_sequence.each do |altname|
    val = altname.value
    case altname.tag
    when 2
      altnames << ( val )
    when 7
      ip_altnames << ( IPAddr.ntop(val) )
    end
  end
  
  { error: 0, altnames: altnames, ip_altnames: ip_altnames }
end

def verify_cert_chain(cert_file,chain_files)
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
chain_files.push('intermed.crt')
chain_files.push('root.crt');

err1 = verify_cert_altnames("site.crt",['test1.com','blah.com'],0);
if err1 != nil
  puts "Failed Altname Check"
  puts err1
else
  puts "Passed Altname Check"
end

err2 = verify_cert_chain("site.crt",chain_files);
if err2 != nil
  puts "Failed Chain Check"
  puts err2
else
  puts "Passed Chain Check"
end
