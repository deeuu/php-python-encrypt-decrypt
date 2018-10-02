<?php
require_once('../mycipher.php');

$cipher = new MyCipher('1234', 'my_key');
$secret = 'secret';

echo "~~~";
$encrypted = $cipher->encrypt($secret);
echo "\nencrypted: " . $encrypted;
$decrypted = $cipher->decrypt($encrypted);
echo "\ndecrypted: " . $decrypted;

echo "\n~~~";
$cipher = new MyCipher();
$encrypted = $cipher->encrypt_includes_iv($secret);
echo "\nEncrypted msg, shipped with IV: ", $encrypted;

$decrypted = $cipher->decrypt_includes_iv($encrypted);
echo "\nDecrypted: ", $decrypted;

?>
