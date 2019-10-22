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
  csr_obj = OpenSSL::X509::Request.new(csr)
  result = Hash.new

  subject_array = csr_obj.subject.to_a
  cn = subject_array.select{|name, _, _| name == 'CN' }.first[1]
  o = subject_array.select{|name, _, _| name == 'O' }.first[1]
  ou = subject_array.select{|name, _, _| name == 'OU' }.first[1]
  st = subject_array.select{|name, _, _| name == 'ST' }.first[1]
  c = subject_array.select{|name, _, _| name == 'C' }.first[1]
  l = subject_array.select{|name, _, _| name == 'L' }.first[1]

  result[:CN] = cn
  result[:O] = o
  result[:OU] = ou
  result[:ST] = st
  result[:C] = c
  result[:L] = l

  attributes = csr_obj.attributes
  return nil if not attributes

  seq = nil
  values = nil

  attributes.each do |a|
    if a.oid == 'extReq'
      seq = a.value
      break
    end
  end
  return nil if not seq

  seq.value.each do |v|
    v.each do |v|
      if v.value[0].value == 'subjectAltName'
        values = v.value[1].value
        break
      end
      break if values
    end
  end
  return nil if not values

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
  LOG.info("Parsed CSR fields:\n #{result.inspect}")
  return result
end
