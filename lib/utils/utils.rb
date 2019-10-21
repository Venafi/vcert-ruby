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