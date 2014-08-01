<?php
/** PHP/PREPEND SECURITY SYSTEM
 *
 * Простенький скрипт, реализующий защиту от несанкционированного
 * запуска "левых" скриптов.
 *
 * 2013 (C) InSysd
 */

/** ------------------------ Главные настройки ----------------------------- **/

/* - Текущий способ работы скрипта:
 *
 *    false - режим обучения (STUDY). Режим в котором будут запоминаться все
 * обращения к скриптам, чтобы составить список "легальных" скриптов
 *
 *	  true - "боевой" режим (BLOCK). Режим в котором будут блокироваться все
 * обращения к скриптам которые отсутствуют в списке разрешенных. Внимание! При
 * переходе в этот режим не забудьте установить запрет на запись в данный файл
 * и в файл БД определенный в разделе конфигурация.
 */
define('PSS_STATUS_BLOCK', true);


/** ---------------------------- Конфигурация ------------------------------ **/
$pss_config=array();

/* - Список допустимых IP администратора
 * Он имеет доступ ко всем скриптам вне зависимости от режима. Его действия не
 * будут влиять на стадии режима обучения.
 */
$pss_config['admin_ip_list']=array(
	//'1.*',
	//'1.1.*',
	//'1.*.*.*',
	'127.0.0.1',
	'192.168.0.*'
);

/* - Email админа
 * На данный почтовый ящик будут высылаться уведомления о несанкционированных
 * попытках запуска неразрешенных скриптов (данную функциональность можно
 * отключить)
 */
$pss_config['admin_email']='admin@site';

/* - Тип блокировки в режиме блокировки
 * 0 - не блокировать запросы (будет отсылаться только email на почту админа
 * если это разрешенно)
 * 1 - блокировать запросы и выводить сообщение о блокировке
 * 2 - блокировать запросы и выводить ошибку 403
 */
$pss_config['block_type']=2;

/* - Высылать администратору письмо с уведомлением
 * Будет высылаться письмо уведомляющее администратора о попытке запуска
 * неразрешенных скриптов
 *
 * 0 - не высылать уведомление
 * 1 - высылать краткое описание события
 * 2 - высылать развернутое описание, включает в себя заголовки ответа и строку
 * пост запроса
 */
$pss_config['alarm_block_send_email']=2;

/* - Уровень ошибок выводимых в браузер
 * Предупреждения будут выводится в браузер. Это может нарушить нормальную
 * работу сайтов.
 * 0 - отключить вывод ошибок
 * 1 - вывод критичных ошибок (Warning)
 * 2 - вывод критичных ошибок (Warning) и замечений (Notice)
 */
$pss_config['alarm_html_level']=2;

/* - Вывод ошибок в браузер только для админа
 * Ошибки и предупреждения будут демонстрироваться только администратору
 * определенному по его IP адресу
 */
$pss_config['alarm_html_only_admin']=true;

/* - Файл БД
 * Файл в котором будут хранится данные о допустимых скриптах. В режиме обучения
 * необходим доступ на запись. В боевом режиме запись должна быть запрещенна.
 */
$pss_config['file_data']='data.txt';


/** ---------------------- Дополнительные параметры ------------------------ **/
/**Внимание! При изменении параметров в данном разделе необходимо заново
 * создать базу данных с нуля */

/* - Способ подсчета контрольной суммы
 * Допустимо: crc, md5, sha
 */
$pss_config['control_crc_method']='md5';

/* - Контролировать имя домена
 * Включить ведение разных логов для разных доменов
 */
$pss_config['path_control_domain']=true;

/* - Контролировать номер порта
 * Включить ведение разных логов для разных локальных портов
 */
$pss_config['path_control_port']=false;

/* - Нормализация имени домена
 * При включении данной директивы будет удален начальный поддомен "www." из имени
 * домена
 */
$pss_config['path_strip_domain']=true;


/** -------------------------- Основной класс ------------------------------ **/

class PssMain{
	const
		STATUS_STUDY=false;

	const
		STATUS_BLOCK=true;

	const
		ERROR_NOTICE=1;

	const
		ERROR_WARNING=2;

	const
		FILE_DATA_SEPARATOR='|';

	/** Метод работы скрипта (блокировать/обучаться)
	 * @var boolean */
	private $status=self::STATUS_STUDY;

	/** Набор с конфигурацией работы скрипта
	 * @var array */
	private $config=array();

	/** Статус запуска класса (true - класс запущен, false - произошли ошибки)
	 * @var boolean */
	private $inited=false;

	/** База данных с индетификаторами разрешенных файлов
	 * @var array */
	private $file_data=array();

	/** Флаг изменения база данных
	 * @var boolean */
	private $file_data_changed=false;


	function __construct($is_status_block, $config_array){
		$this->inited=false;

		if(!is_array($config_array)){
			trigger_error(__METHOD__.': input var "$config_array" must be an array', E_USER_WARNING);
			return false;
		}

		if(!is_scalar($is_status_block)){
			trigger_error(__METHOD__.': input var "$is_status_block" must be a scalar', E_USER_WARNING);
			return false;
		}

		$this->config=$config_array;

		if($is_status_block){
			$this->status=self::STATUS_BLOCK;
		}else{
			$this->status=self::STATUS_STUDY;
		}

		$this->inited=true;
	}

	/** Имеет ли пользователь статус админа
	 *
	 * @return boolean
	 */
	protected function IsAdmin(){
		if(isset($_SERVER['REMOTE_ADDR']) && !empty($_SERVER['REMOTE_ADDR'])){
			$ip_list=$this->GetConfig('admin_ip_list');

			$ip_user=$_SERVER['REMOTE_ADDR'];

			foreach($ip_list as $ip){
				$ip=trim($ip);
				if(empty($ip))continue;

				$tmp=explode('.', $ip);

				$pattern=array_fill(0, 4, '[0-9]{1,3}');

				for($i=0; ($i<count($tmp) && $i<4); $i++){
					if(is_numeric($tmp[$i])){
						$pattern[$i]=$tmp[$i];
					}
				}

				if(preg_match('#^'.implode('\.', $pattern).'$#', $ip_user)){
					return true;
				}
			}
		}

		return false;
	}

	/** Запуск работы
	 *
	 * @return boolean
	 */
	function Process(){
		if(!$this->inited){
			return false;
		}

		if(!$this->ProcessBDLoad()){
			return false;
		}

		if(!$this->IsAdmin()){
			$page_hash=$this->GetFileHash();

			if($this->GetStatus()==self::STATUS_BLOCK){
				$this->ProcessStatusBlock($page_hash);
			}elseif($this->GetStatus()==self::STATUS_STUDY){
				$this->ProcessStatusStudy($page_hash);
			}
		}

		if(!$this->ProcessBDSave()){
			return false;
		}
	}

	/** Режим обучения
	 *
	 * @param string $page_hash
	 */
	protected function ProcessStatusStudy($page_hash){
		if(!$this->ProcessBDExists($page_hash)){
			$this->ProcessBDAdd($page_hash);
		}
	}

	/** Режим блокирования
	 *
	 * @param string $page_hash
	 */
	protected function ProcessStatusBlock($page_hash){
		if($this->ProcessBDExists($page_hash) || $this->IsAdmin()){
			return true;
		}

		if($this->GetConfig('block_type')==1){
			$this->PrintBlock();
		}elseif($this->GetConfig('block_type')==2){
			$this->PrintForbidden();
		}

		if($this->GetConfig('alarm_block_send_email')>0 && strlen($this->GetConfig('admin_email'))>0){
			$this->SendAdminEmail();
		}

		if($this->GetConfig('block_type')>0){
			die();
		}
	}

	/** Добавляем новую запись в базу
	 *
	 * @param string $new_hash
	 * @return boolean
	 */
	protected function ProcessBDAdd($new_hash){
		if(!$this->ProcessBDExists($new_hash)){
			$this->file_data[]=$new_hash;
			$this->file_data_changed=true;
		}else{
			return true;
		}
	}

	/** Проверка существования записи в базе
	 *
	 * @param string $hash
	 * @return boolean
	 */
	protected function ProcessBDExists($hash){
		return in_array($hash, $this->file_data);
	}

	/** Проверка файла БД
	 *
	 * @return boolean
	 */
	protected function ProcessBDLoad(){
		$path_data_file=dirname(__FILE__).'/'.$this->GetConfig('file_data');

		if(!file_exists($path_data_file)){
			$this->PrintError('Файл базы не найден!', self::ERROR_WARNING);
			return false;
		}

		if(!is_readable($path_data_file)){
			$this->PrintError('Файл базы не доступен для чтения', self::ERROR_WARNING);
			return false;
		}

		if($this->GetStatus()==self::STATUS_BLOCK){
			if(is_writable($path_data_file)){
				$this->PrintError('Файл базы доступен для записи.'."\n".'Запретите запись в файл базы!', self::ERROR_NOTICE);
			}
		}else{
			if(!is_writable($path_data_file)){
				$this->PrintError('Файл базы не доступен для записи в обучающем режиме.'."\n".'Разрешите запись в файл базы!', self::ERROR_NOTICE);
			}
		}

		$data_string=@file_get_contents($path_data_file);
		$data_string=trim($data_string);

		if(strlen($data_string)>0){
			$this->file_data=explode(self::FILE_DATA_SEPARATOR, $data_string);
		}

		if($this->GetStatus()==self::STATUS_BLOCK){
			if(count($this->file_data)==0){
				$this->PrintError('Файл базы данных пуст (нет ни одного разрешенного скрипта)', self::ERROR_NOTICE);
			}
		}

		return true;
	}

	/** Запись изменений в базу
	 *
	 */
	protected function ProcessBDSave(){
		if($this->file_data_changed){
			$path_data_file=dirname(__FILE__).'/'.$this->GetConfig('file_data');

			if(is_writable($path_data_file)){
				$data_string=implode(self::FILE_DATA_SEPARATOR, $this->file_data);
				file_put_contents($path_data_file, $data_string);

				return true;
			}else{
				return false;
			}
		}

		return true;
	}

	/** Отправка уведомления на администраторский email
	 *
	 */
	protected function SendAdminEmail(){
		$mail_subject='PSS: обращение к неразрешенной странице';

		$mail_body=array();
		$mail_body[]='Дата: '.date('d.m.Y H:i:s');
		$mail_body[]='Ip адрес пользователя: '.$_SERVER['REMOTE_ADDR'];
		$mail_body[]='--------------------------------------------';

		if(strlen($this->GetFileStringDomain())>0){
			$mail_body[]='Домен: '.$this->GetFileStringDomain();
		}

		if(!empty($_SERVER['REQUEST_URI'])){
			$mail_body[]='Запрос: '.$_SERVER['REQUEST_URI'];
		}

		if(strlen($this->GetFileStringName())>0){
			$mail_body[]='Файл: '.$this->GetFileStringName();
		}

		$mail_body[]='--------------------------------------------';

		if($this->GetConfig('alarm_block_send_email')==2){
			//Подробный отчет
			if(!empty($_SERVER['REQUEST_METHOD'])){
				$mail_body[]='Тип запроса: '.$_SERVER['REQUEST_METHOD'];
			}

			$mail_body[]='--------------------------------------------';

			//Получение заголовков пакета
			$headers=array();
			if (!function_exists('getallheaders')){
				foreach($_SERVER as $key=>$value){
					if(substr($key,0,5)=="HTTP_"){
						$key=str_replace(" ","-",ucwords(strtolower(str_replace("_"," ",substr($key,5)))));
						$headers[$key]=$value;
					}
				}
			}else{
				$headers=getallheaders();
			}

			if(count($headers)>0){
				$mail_body[]='Заголовки: ';
				$mail_body[]='';

				foreach($headers as $key=>$value){
					$tmp=$key.': '.$value;
					if(strlen($tmp)>1024){
						$tmp=substr($tmp, 0, 1024).'[......]';
					}

					$mail_body[]=$tmp;
				}

				$mail_body[]='--------------------------------------------';
			}

			if(!empty($_POST)){
				$mail_body[]='Пост запрос: ';
				$mail_body[]='';

				$tmp=array();
				foreach($_POST as $key=>$value){
					$tmp[]=$key.'='.urlencode($value);
				}

				$tmp=implode('&', $tmp);
				if(strlen($tmp)>1024){
					$tmp=substr($tmp, 0, 1024).'[......]';
				}

				$mail_body[]=$tmp;
				$mail_body[]='--------------------------------------------';
			}
		}

		if($this->GetConfig('block_type')>0){
			$mail_body[]='Запрос заблокирован. Высланно данное уведомление.';
		}else{
			$mail_body[]='Запрос не был заблокирован согласно конфигурации. Высланно данное уведомление.';
		}

		//Письмо отсылаем в кодировке UTF-8
		$mail_headers=array(
			'MIME-Version: 1.0',
			'Content-Type: text/plain; charset="UTF-8";'
		);

		$mail_subject='=?UTF-8?B?' . base64_encode($mail_subject) . '?=';

		@mail($this->GetConfig('admin_email'), $mail_subject, implode("\r\n",  $mail_body), implode("\n", $mail_headers));
	}

	/** Вывод ошибки в браузер
	 *
	 * @param string $error_message
	 * @param integer $error_level
	 */
	protected function PrintError($error_message, $error_level=self::ERROR_NOTICE){
		if($this->GetConfig('alarm_html_only_admin') && !$this->IsAdmin()){
			return true;
		}


		if($error_level > $this->GetConfig('alarm_html_level')){
			return true;
		}

		switch($error_level){
			case self::ERROR_NOTICE:
				$error_title='Внимание!'; break;

			case self::ERROR_WARNING:
				$error_title='Критическая ошибка!'; break;
		}

		$error_message='Php Prepend Security System'.'\n\n'.htmlspecialchars($error_title).'\n'.htmlspecialchars($error_message).'\n\n'.htmlspecialchars('PSS (c) InSys 2013');
		$error_message=str_replace("\r", '\n', $error_message);
		$error_message=str_replace("\n", '\n', $error_message);

		echo('<script>alert("'.$error_message.'");</script>');
	}

	/** Вывод ошибки в браузер
	 *
	 * @param string $error_message
	 * @param integer $error_level
	 */
	protected function PrintBlock(){
		echo('Sorry, access to this page is blocked by PSS');
	}

	/** Вывод ошибки в браузер
	 *
	 */
	protected function PrintForbidden(){
		if(!isset($_SERVER['SERVER_SIGNATURE']) || empty($_SERVER['SERVER_SIGNATURE'])){
			$_SERVER['SERVER_SIGNATURE']='Apache/2.2.4 (FreeBSD) mod_ssl/2.2.4 OpenSSL/0.9.8d PHP/5.2.4 Server at '.((!empty($_SERVER['HTTP_HOST']))?empty($_SERVER['HTTP_HOST']):'localhost').' Port '.((!empty($_SERVER['SERVER_PORT']))?empty($_SERVER['SERVER_PORT']):'80');
		}

		if(!headers_sent()){
			header("HTTP/1.0 403 Forbidden");
			header("HTTP/1.1 403 Forbidden");
			header("Status: 403 Forbidden");
		}

		echo('<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don\'t have permission to access '.((!empty($_SERVER['SCRIPT_NAME']))?$_SERVER['SCRIPT_NAME']:'this page').' on this server.</p>
<hr>
<address>'.$_SERVER['SERVER_SIGNATURE'].'</address>
</body></html>');
	}

	/** Получить значение из конфига
	 *
	 * @param array $conf_section_name
	 * @return mixed
	 */
	protected function GetConfig($conf_section_name){
		if(!is_scalar($conf_section_name)){
			trigger_error(__METHOD__.': input var "$conf_section_name" must be a scalar', E_USER_WARNING);
			return false;
		}

		if(array_key_exists($conf_section_name, $this->config)){
			return $this->config[$conf_section_name];
		}else{
			trigger_error(__METHOD__.': undefined config section index: '.htmlspecialchars($conf_section_name), E_USER_NOTICE);
			return false;
		}
	}

	/** Режим работы скрипта (блокирование - true, обучение - false)
	 *
	 * @return boolean
	 */
	protected function GetStatus(){
		return $this->status;
	}

	/** Получить хеш сумму (индетификатор) запущенного скрипта
	 *
	 * @return string
	 */
	protected function GetFileHash(){
		$hash_func='md5';

		switch(strtolower($this->GetConfig('control_crc_method'))){
			case 'crc': case 'crc32':
				$hash_func='crc32'; break;

			case 'md5':
				$hash_func='md5'; break;

			case 'sha': case 'sha1':
				$hash_func='sha1'; break;

			default:
				$hash_func='md5'; break;
		}

		$file_string=$this->GetFileString();

		if(function_exists($hash_func) && is_callable($hash_func)){
			$result=$hash_func($file_string);
		}else{
			trigger_error(__METHOD__.': unknown hash function: '.htmlspecialchars($conf_section_name), E_USER_NOTICE);
			$result=base64_encode($file_string);
		}

		return $result;
	}


	/** Получить адрес запущенного скрипта
	 *
	 * Формат: домен:порт:путь к файлу
	 * Домен и/или порт могут отсутствовать в зависимости от настроек скрипта.
	 *
	 * @return string
	 */
	protected function GetFileString(){
		$result=array();

		if($this->GetConfig('path_control_domain')){
			$result[]=(string)$this->GetFileStringDomain();
		}

		if($this->GetConfig('path_control_port')){
			$result[]=(string)$this->GetFileStringPort();
		}

		$result[]=(string)$this->GetFileStringName();

		return implode(':', $result);
	}

	/** Получить имя запрошенного файла
	 *
	 * @return string
	 */
	private function GetFileStringName(){
		if(isset($_SERVER['SCRIPT_NAME']) && !empty($_SERVER['SCRIPT_NAME'])){
			$result=$_SERVER['SCRIPT_NAME'];
		}elseif(isset($_SERVER['SCRIPT_FILENAME']) && !empty($_SERVER['SCRIPT_FILENAME'])){
			$result=$_SERVER['SCRIPT_FILENAME'];
		}else{
			$result='';
		}

		$result=str_replace('\\', '/', $result);
		$result=preg_replace('#/+#', '/', $result);
		$result=trim($result, '/');

		$result=strtolower($result);

		return $result;
	}

	/** Получить имя запрошенного домена
	 *
	 * @return string
	 */
	private function GetFileStringDomain(){
		$result='';

		if(isset($_SERVER['HTTP_HOST']) && !empty($_SERVER['HTTP_HOST'])){
			$result=$_SERVER['HTTP_HOST'];
		}elseif(isset($_SERVER['SERVER_NAME']) && !empty($_SERVER['SERVER_NAME'])){
			$result=$_SERVER['SERVER_NAME'];
		}elseif(isset($_SERVER['SERVER_ADDR']) && !empty($_SERVER['SERVER_ADDR'])){
			$result=$_SERVER['SERVER_ADDR'];
		}else{
			$result='';
		}

		$result=strtolower($result);

		if($this->GetConfig('path_strip_domain')){
			$result=preg_replace('#^www\.#i', '', $result);
		}

		return $result;
	}

	/** Получить номер запрошенного порта
	 *
	 * @return string
	 */
	private function GetFileStringPort(){
		$result='';

		if(isset($_SERVER['SERVER_PORT']) && !empty($_SERVER['SERVER_PORT'])){
			$result=$_SERVER['SERVER_PORT'];
		}else{
			$result='80';
		}

		return $result;
	}
}


/** --------------------------- Тело скрипта ------------------------------- **/
//Инициализируем и запускаем основной класс
$pss_class=new PssMain(PSS_STATUS_BLOCK, $pss_config);
$pss_class->Process();

//Не засоряем глобальное пространство
unset($pss_class, $pss_config);
