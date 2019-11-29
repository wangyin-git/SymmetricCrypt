require 'openssl'
require 'json'
require 'base64'

class SymmetricCrypt
  private

  attr_accessor :encrypt_cipher, :encrypt_chunk, :algorithm, :_key, :_iv, :decrypt_cipher, :decrypt_chunk

  public

  def self.from_encrypt_symmetric_key(rsa, encrypt)
    h = JSON.parse(rsa.private_decrypt(encrypt))
    SymmetricCrypt.new(algorithm: h["algorithm"],
                       key:       Base64.decode64(h["key"]),
                       iv:        Base64.decode64(h["iv"]))
  end

  def self.random_key_iv(algorithm: 'AES-128-CBC')
    cipher = OpenSSL::Cipher.new(algorithm)
    [cipher.random_key, cipher.random_iv]
  end

  def initialize(algorithm: 'AES-128-CBC', key: nil, iv: nil)
    self.algorithm      = algorithm
    self.encrypt_cipher = OpenSSL::Cipher.new(algorithm)
    self.decrypt_cipher = OpenSSL::Cipher.new(algorithm)
    self.encrypt_chunk  = ""
    self.decrypt_chunk  = ""
    encrypt_cipher.encrypt
    if key
      encrypt_cipher.key = key
      self._key          = key
    else
      self._key = encrypt_cipher.random_key
    end
    if iv
      encrypt_cipher.iv = iv
      self._iv          = iv
    else
      self._iv = encrypt_cipher.random_iv
    end

    decrypt_cipher.decrypt
    decrypt_cipher.key = _key
    decrypt_cipher.iv  = _iv
  end

  public

  def get_encrypt_symmetric_key(rsa)
    rsa.public_encrypt("{\"algorithm\": \"#{algorithm}\", \"key\": \"#{Base64.strict_encode64(_key)}\", \"iv\": \"#{Base64.strict_encode64(_iv)}\"}")
  end

  def update_encrypt_data(data, finish: false)
    if data.length > 0
      encrypt_chunk << encrypt_cipher.update(data)
    end
    if finish
      encrypt_chunk << encrypt_cipher.final
      res = encrypt_chunk[0..-1]
      encrypt_reset
      res
    else
      -encrypt_chunk
    end
  end

  def update_decrypt_data(data, finish: false)
    if data.length > 0
      decrypt_chunk << decrypt_cipher.update(data)
    end
    if finish
      decrypt_chunk << decrypt_cipher.final
      res = decrypt_chunk[0..-1]
      decrypt_reset
      res
    else
      -decrypt_chunk
    end
  end

  def encrypt_reset
    encrypt_cipher.reset
    self.encrypt_chunk = ""
  end

  def decrypt_reset
    decrypt_cipher.reset
    self.decrypt_chunk = ""
  end

end
