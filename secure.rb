SECRET = 'secreto himitsu secret'

def hash_string(s)
  return OpenSSL::HMAC.hexdigest('MD5', SECRET, s)
end

def make_secure_value(s)
   return s + ',' + hash_string(s)
end

def get_value_from_hash(h)
  h =~ /^([^,]*),(.*)/

  if h == make_secure_value($1)
    return $1
  else
    return nil
  end
end

def make_salt()
  prng = Random.new

  salt = ''
  characters = ('a'..'z').to_a + ('A'..'Z').to_a + ('0'..'9').to_a
  5.times do
    salt << characters[prng.rand(62)]
  end
  return salt
end

def make_password_hash(name, password, salt = nil)
  salt = make_salt if !salt
  return OpenSSL::Digest.hexdigest('SHA256', name + password + salt) + ',' + salt
end

def check_for_validity(name, password, h)
  h =~ /^([^,]*),(.*)/
  salt = $2
  if h == make_password_hash(name, password, salt)
    true
  end
end


