<?php
if(session_id() == ""){ session_start(); }

class Auth{

	private $ip;
	private $user;
	private $pwd;
	private $table;
	private $columnIdent = "username";
	private $columnpwd   = "password";
	private $connectiondb;
	private $account;
	private $use_otp = false;
	private $otp_columnName = "otpsecret";
	private $base32Table= array('A', 'B', 'C', 'D', 'E', 'F', 'G', 'H','I', 'J', 'K', 'L', 'M', 'N', 'O', 'P','Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X','Y', 'Z', '2', '3', '4', '5', '6', '7','=');
	private $hashAlgo = "sha512";
	private $hashSalt = "default";
	private $hashIter = 10000;

	public $db_connected = false;
	public $db_error;

	public function __construct($arr){
		
		if(isset($_SESSION['__dataAccount__'])){
			$this->account = $_SESSION['__dataAccount__'];
		}

		if(
			gettype($arr)=="array" AND
			isset($arr['db_address']) AND
			isset($arr['db_user']) AND
			isset($arr['db_pwd']) AND
			isset($arr['db_table'])
		){
			$this->ip 	 = $arr['db_address'];
			$this->user  = $arr['db_user'];
			$this->pwd 	 = $arr['db_pwd'];
			$this->name  = $arr['db_name'];
			$this->table = $arr['db_table'];


			if(isset($arr['db_columnIdent']) AND is_string($arr['db_columnIdent'])){$this->columnIdent = $arr['db_columnIdent'];}
			if(isset($arr['db_columnPwd']) AND is_string($arr['db_columnPwd'])){$this->columnPwd = $arr['db_columnPwd'];}

			if(isset($arr['use_otp']) AND is_bool($arr['use_otp']) ){$this->use_otp = $arr['use_otp'];}
			if(isset($arr['otp_columnName']) AND is_string($arr['otp_columnName'])){$this->otp_columnName = $arr['otp_columnName'];}

			if(isset($arr['hash_algo']) AND is_string($arr['hash_algo'])){$this->hashAlgo = $arr['hash_algo'];}
			if(isset($arr['hash_salt']) AND is_string($arr['hash_salt'])){$this->hashSalt = $arr['hash_salt'];}
			if(isset($arr['hash_iter']) AND is_int($arr['hash_iter'])){$this->hashIter = $arr['hash_iter'];}


			try{ 
				$this->connectiondb = new PDO('mysql:host='.$this->ip.';dbname='.$this->name, $this->user, $this->pwd);
				$this->db_connected = true;
			}catch(Exception $e){
				$this->db_error = $e->getMessage();
			}
		}else{

		}
	}

	public function hashPwd($password,$algo="sha512",$salt="",$iter=10000){

		$validAlgo = hash_algos();

		if(isset($password) AND is_string($password)){
			if(in_array($algo, $validAlgo)){
				if(is_string($salt)){
					if(is_int($iter) AND $iter>1){
						$hashPassword = hash_pbkdf2($algo, $password, $salt, $iter, 0);
						return Array('hashPwd'=>true,'error'=>'','hashPassword'=>$hashPassword);
					}else return Array('hashPwd'=>false,'error'=>'iteration isn\'t valid or too small');
				}else return Array('hashPwd'=>false,'error'=>'salt isn\'t valid');
			}else return Array('hashPwd'=>false,'error'=>'Hash algo isn\'t valid');
		}else return Array('hashPwd'=>false,'error'=>'Password isn\'t valid');
	}

	public function validatorId($user, $password, $hash=null, $iter=null){
		if($hash === null){ $hash=$this->hashSalt; }
		if($iter === null){ $iter=$this->hashIter; }
		if($this->db_connected == true){

			$hashPwd = $this->hashPwd($password,$this->hashAlgo,$hash,$iter);

			if($hashPwd['hashPwd']){

				$password = $hashPwd['hashPassword'];

			}else return Array('validatorId'=>false,'error'=>$hashPwd['error']);

			$test = $this->connectiondb->prepare('SELECT * FROM '.$this->table.' WHERE '.$this->columnIdent.' = :username AND '.$this->columnpwd.'="'.$password.'"');

			$test->execute(array(
				":username" => $user,
				)); 

			$this->account = $test->fetch();
			$_SESSION['__dataAccount__'] = $this->account;

			$testcount = $test->rowCount();
			if($testcount==1){

				return Array('validatorId'=>true,'error'=>'');

			}else{

				return Array('validatorId'=>false,'error'=>'Wrong login');

			}

		}else return Array('validatorId'=>false,'error'=>'DB not connected');
	}

	private function coUser(){
		$_SESSION['id'] = $this->account['id'];
		$_SESSION['connected'] = true;
		return array('connection'=>true,'error'=>'');
	}

	private function _32Decode($secret)
    {
        if (empty($secret)) { return ''; }
        $base32chars = $this->base32Table;
        $base32charsFlipped = array_flip($base32chars);
        $paddingCharCount = substr_count($secret, $base32chars[32]);
        $allowedValues = array(6, 4, 3, 1, 0);
        if (!in_array($paddingCharCount, $allowedValues)) { return false;}
        for ($i = 0; $i < 4; ++$i) { if ($paddingCharCount == $allowedValues[$i] && substr($secret, -($allowedValues[$i])) != str_repeat($base32chars[32], $allowedValues[$i])) {return false;}}
        $secret = str_replace('=', '', $secret);
        $secret = str_split($secret);
        $binaryString = '';
        for ($i = 0; $i < count($secret); $i = $i + 8) {$x = ''; if (!in_array($secret[$i], $base32chars)) {return false;} for ($j = 0; $j < 8; ++$j) { $x .= str_pad(base_convert(@$base32charsFlipped[@$secret[$i + $j]], 10, 2), 5, '0', STR_PAD_LEFT);} $eightBits = str_split($x, 8); for ($z = 0; $z < count($eightBits); ++$z) {$binaryString .= (($y = chr(base_convert($eightBits[$z], 2, 10))) || ord($y) == 48) ? $y : '';}}
        return $binaryString;
    }

	private function getCode($secret, $timeSlice = null)
    {
        if ($timeSlice === null) {$timeSlice = floor(time() / 30);}
        $secretkey = $this->_32Decode($secret);
        $codeLength = 6;
        $time = chr(0).chr(0).chr(0).chr(0).pack('N*', $timeSlice);
        $hm = hash_hmac('SHA1', $time, $secretkey, true);
        $offset = ord(substr($hm, -1)) & 0x0F;
        $hashpart = substr($hm, $offset, 4);
        $value = unpack('N', $hashpart);
        $value = $value[1];
        $value = $value & 0x7FFFFFFF;
        $modulo = pow(10, $codeLength);
        return str_pad($value % $modulo, $codeLength, '0', STR_PAD_LEFT);
    }
    private function timecode($s, $u)
    {
        if (function_exists('hash_equals')) { return hash_equals($s, $u); }
        $safeLen = strlen($s);
        $userLen = strlen($u);
        if ($userLen != $safeLen) { return false; }
        $result = 0;
        for ($i = 0; $i < $userLen; ++$i) {
            $result |= (ord($s[$i]) ^ ord($u[$i]));
        }
        return $result === 0;
    }
    public function validatorOTP($secret, $code, $aro = 1)
    {

        if (strlen($code) != 6) { return false; }
        for ($i = -$aro; $i <= $aro; ++$i) {
            $calculatedCode = $this->getCode($secret, floor(time() / 30) + $i);
            if ($this->timecode($calculatedCode, $code)) {
                return true;
            }
        }
        return false;
    }

	public function connection($user, $password, $otp=false, $hash=null, $iter=null, $booldel=false){
		if($hash === null){ $hash=$this->hashSalt; }
		if($iter === null){ $iter=$this->hashIter; }

		$user = str_replace('"', "", $user);
		$user = str_replace("'", "", $user);
		$user = htmlentities($user);
		$password = htmlentities($password);

		if($this->db_connected == true){

			if($this->validatorId($user,$password,$hash,$iter)["validatorId"]==true){


				if($booldel==true){
					session_destroy();
				}

				if(!isset($_SESSION['connected']) OR $_SESSION['connected']==false){
					if($this->use_otp){
						if(isset($this->account[$this->otp_columnName])){

							if($this->account[$this->otp_columnName]!="0"){
								
								$otpSecretKey = $this->account[$this->otp_columnName];

								if(strlen($otpSecretKey)>=6 OR strlen($otpSecretKey)<=128){

									if(is_string($otpSecretKey)){

										if($otp==false){
											$_SESSION['id'] = $this->account['id'];
											$_SESSION['connected'] = false;
											$_SESSION['otpneed'] = true;
											return array('connection'=>false,'error'=>'Connection need otp code','otpneed'=>true);

										}else{
											if(isset($otp) AND is_numeric($otp) AND strlen($otp)==6){
												if($this->validatorOTP($otpSecretKey, $otp, 2)){
													$_SESSION['id'] = $this->account['id'];
													$_SESSION['connected'] = true;
													$_SESSION['otpneed'] = true;
													return array('connection'=>true,'error'=>'','otpneed'=>false);
												}else return Array('connection'=>true,'error'=>'OTP key isn\'t valid','otpneed'=>true);
											}else return Array('connection'=>true,'error'=>'OTP key isn\'t valid','otpneed'=>true);
										}

									}else return array('connection'=>false,'error'=>'Bad OTP key');

								}else return array('connection'=>false,'error'=>'Bad OTP key');

							}else return $this->coUser();

						}else return array('connection'=>false,'error'=>'Bad otp_columnName');
					}else{
						return $this->coUser();
					}
				}else{
					return array('connection'=>false,'error'=>'This account is already connected');
				}

			}else{

				return array('connected'=>false,'error'=>'Wrong login');

			}

		}else return Array('error'=>'DB not connected');
	}

	public function logout(){
		if(session_id() != ""){
			session_destroy();
		}
		$this->account = '';
		return array('logout'=>true,'error'=>'');
	}

	public function getAccount($val=false){
		if($val!=false){
			if(gettype($val)=="string"){
				if(isset($this->account[$val])){
					return array('getAccount'=>true,'error'=>'','data'=>$this->account[$val]);
				}else return array('getAccount'=>false,'error'=>'This value does not exist','data'=>'');
			}else return array('getAccount'=>false,'error'=>'Bad value','data'=>'');
		}else{
			return array('getAccount'=>true,'error'=>'','data'=>$this->account);
		}
	}

}

?>
