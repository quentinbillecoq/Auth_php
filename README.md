# Auth_php
Auth PHP system simple and secure

# Usage
In first, you must download and place the lib folder in at the root of your site

In your code :
```php
require_once "lib/auth.php";

$auth = new Auth([
    'db_address'         => 'localhost',
    'db_user'            => 'your_db_user',
    'db_pwd'             => 'your_db_password',
    'db_name'            => 'your_db_name',
    'db_table'           => 'your_db_table',
    'db_columnIdent'     => 'username',          //dispensable default=username
    'db_columnPwd'       => 'password',          //dispensable default=password
    'use_otp'            => false,               //dispensable default=false
    'otp_columnName'     => "otpsecret",         //dispensable default=otpsecret
    'hash_algo'          => "sha512",            //dispensable default=sha512
    'hash_salt'          => "default",           //dispensable default=default
    'hash_iter'          => 10000,               //dispensable default=10000
]);
```

# Make a new user connection
Function ***connection***
```php
$auth->connection( string $user , string $password [, bool $otp = false [, string $hash = null [, int $iter = null [, bool $booldel = false ]]]] )
```
### Exemple :
Code :
```php
$auth->connection("usertest","test");
```
Output if connection is valid :
```php
array(2) { ["connection"]=> bool(true) ["error"]=> string(0) "" } 
```

# Hash password for new user
Function ***hashPwd***
```php
$auth->hashPwd( string $password [, string $algo = "sha512" [, string $salt = "" [, int $iter = null]]] )
```
Code :
```php
$auth->hashPwd("password");

$auth->hashPwd("password")["hashPassword"];
```
Output :
```php
array(3) { ["hashPwd"]=> bool(true) ["error"]=> string(0) "" ["hashPassword"]=> string(128) "f4ca507c07d0bd31bc779a08756826a6fd9dd97d43ac25e4b29a0933abea03f31fa1234792ff981f335ba91b0ab40e32643c5cc0dbd343ed6b1c61f1ee6ad559" } 

"f4ca507c07d0bd31bc779a08756826a6fd9dd97d43ac25e4b29a0933abea03f31fa1234792ff981f335ba91b0ab40e32643c5cc0dbd343ed6b1c61f1ee6ad559" 
```

# Logout user
Function ***logout***
```php
$auth->logout();
```
Code :
```php
$auth->logout();
```
Nothing in output !

# Get account info
Function ***getAccount***

Return false if the user isn't connected
```php
$auth->getAccount( [ string $val = false ] )
```
Code :
```php
$auth->getAccount();

$auth->getAccount("username");

$auth->getAccount("username")["data"]
```
Output :
```php
array(3) { ["getAccount"]=> bool(true) ["error"]=> string(0) "" ["data"]=> array(6) { ["id"]=> string(1) "2" [0]=> string(1) "2" ["username"]=> string(12) "usertest" [1]=> string(12) "usertest" ["password"]=> string(128) "4048941cb4d076df00db7466c8762ac127bfa33cce22f05889ee2361d5b292b07d6296e770c15a258e88057379907db4399e0da5e5204686bd72390476ed4365" [2]=> string(128) "4048941cb4d076df00db7466c8762ac127bfa33cce22f05889ee2361d5b292b07d6296e770c15a258e88057379907db4399e0da5e5204686bd72390476ed4365" } } 

array(3) { ["getAccount"]=> bool(true) ["error"]=> string(0) "" ["data"]=> string(12) "usertest" } 

"usertest"
```
