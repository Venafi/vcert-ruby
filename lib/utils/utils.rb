def parse_pem_list(multiline)
  pems = []
  buf = ""
  current_string_is_pem = false
  multiline.each_line do |line|
    if line.match(/-----BEGIN [A-Z\ ]+-----/)
      current_string_is_pem = true
    end
    if current_string_is_pem
      buf = buf + line
    end
    if line.match(/-----END [A-Z\ ]+-----/)
      current_string_is_pem = false
      pems.push(buf)
      buf = ""
    end
  end
  pems
end

def parse_csr_fields(csr)
  LOG.info("Trying to parse CSR:\n#{csr}")
  csr_obj = OpenSSL::X509::Request.new(csr)
  result = Hash.new

  subject_array = csr_obj.subject.to_a
  subject_array.map { |x|
    if x[1] != ""
      result[x[0].to_sym] = x[1]
    end
  }

  attributes = csr_obj.attributes

  seq = nil
  values = nil

  if attributes
    attributes.each do |a|
      if a.oid == 'extReq'
        seq = a.value
        break
      end
    end
    # return nil if not seq
  end

  if seq
    seq.value.each do |v|
      v.each do |v|
        if v.value[0].value == 'subjectAltName'
          values = v.value[1].value
          break
        end
        break if values
      end
    end
    # return nil if not values
  end


  if values
    values = OpenSSL::ASN1.decode(values).value

    values.each do |v|
      case v.tag
      when 2
        result[:DNS] = v.value
      when 7
        case v.value.size
        when 4
          ip = v.value.unpack('C*').join('.')
        when 16
          ip = v.value.unpack('n*').map { |o| sprintf("%X", o) }.join(':')
        else
          STDERR.print "The encountered IP-address is neither IPv4 nor IPv6\n"
          next
        end
        result[:IP] = ip
      else
        STDERR.print "Uknown tag #{v.tag} -- I only know 2 (DNS) and 7 (IP)\n"
      end
    end
  end

  if csr_obj.public_key.instance_of? OpenSSL::PKey::RSA
    result[:key_type] = Vcert::KeyType.new "rsa", csr_obj.public_key.n.num_bits
  elsif csr_obj.public_key.instance_of? OpenSSL::PKey::EC
    # todo: implement
    raise "not implemented"
  else
    raise Vcert::VcertError
  end


  LOG.info("Parsed CSR fields:\n #{result.inspect}")
  return result
end
