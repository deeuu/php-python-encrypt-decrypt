<?php
namespace shared\cipher;

/**
 * Valid encryption methods AES-256-CFB 
 * 
 * $cypher = new MyCypher($iv);
 * $php_encrypted      = $cypher->encrypt('test');
 * $php_decrypted      = $cypher->decrypt($php_encrypted);
 */
class MyCipher {

    private $key = 'asdfa923aksadsYahoasdw998sdsads';
    private $iv = null;
    private $method = "AES-256-CFB";
    private $blocksize = 32;
    private $padwith = '`';

    /*
     * construct for cipher class - get, set key and iv
     */

    function __construct($iv = null, $key = null) {

        $this->key = $key;
        $this->iv = $iv;
        $this->random_iv = openssl_random_pseudo_bytes(16, true);
    }

    /*
     * get hased key - if key is not set on init, then default key wil be used
     */

    private function getKEY() {

        if (empty($this->key)) {
            $this->key = $key;
        }

        return substr(hash('sha256', $this->key), 0, 32);
    }

    /*
     * get hashed IV value - if no IV values then it throw error
     */

    private function getIV() {

        if (empty($this->iv)) {
            $this->iv = $this->random_iv; 
        }

        return substr(hash('sha256', $this->iv), 0, 16);
    }

    /*
     * Encrypt given string using AES encryption standard
     */

    public function encrypt($secret) {

        try {

            $padded_secret = $secret . str_repeat($this->padwith, ($this->blocksize - strlen($secret) % $this->blocksize));
            $encrypted_string = openssl_encrypt($padded_secret, $this->method, $this->getKEY(), OPENSSL_RAW_DATA, $this->getIV());
            $encrypted_secret = base64_encode($encrypted_string);
            return $encrypted_secret;
        } catch (Exception $e) {
            die('Error : ' . $e->getMessage());
        }
    }

    /*
     * Decrypt given string using AES standard
     */

    public function decrypt($secret) {
        try {
            $decoded_secret = base64_decode($secret);
            $decrypted_secret = openssl_decrypt($decoded_secret, $this->method, $this->getKEY(), OPENSSL_RAW_DATA, $this->getIV());
            return rtrim($decrypted_secret, $this->padwith);
        } catch (Exception $e) {
            die('Error : ' . $e->getMessage());
        }
    }
    

    public function encrypt_includes_iv($secret) {

        try {

            $padded_secret = $secret . str_repeat($this->padwith, ($this->blocksize - strlen($secret) % $this->blocksize));
            $encrypted_string = openssl_encrypt($padded_secret, $this->method, $this->getKEY(), OPENSSL_RAW_DATA, $this->getIV());
            $encrypted_secret = base64_encode($this->getIV() . $encrypted_string);

            return $encrypted_secret;
        } catch (Exception $e) {
            die('Error : ' . $e->getMessage());
        }
    }

    public function decrypt_includes_iv($secret) {
        try {
            $decoded_secret = base64_decode($secret);
            $iv_hash = substr($decoded_secret, 0, 16);
            $decoded_secret = substr($decoded_secret, 16);
            $decrypted_secret = openssl_decrypt($decoded_secret, $this->method, $this->getKEY(), OPENSSL_RAW_DATA, $iv_hash);
            return rtrim($decrypted_secret, $this->padwith);
        } catch (Exception $e) {
            die('Error : ' . $e->getMessage());
        }
    }
}
