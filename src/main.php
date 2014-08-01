<?php
/** PHP/PREPEND SECURITY SYSTEM
 *
 * Простенький скрипт, реализующий защиту от несанкционированного
 * запуска "левых" скриптов.
 *
 * Основан на использовании директивы auto_prepend_file и постройки списка
 * разрешенных файлов
 *
 * @see http://intsystem.org/916/security-system-php-site/
 *
 * @author 2013 (C) InSysd
 */
 
 
/** ------------------------ Главные настройки ----------------------------- **/
/* - Текущий способ работы скрипта:
 *
 *    false - режим обучения (STUDY). Режим в котором будут запоминаться все
 * обращения к скриптам, чтобы составить список "легальных" скриптов
 *
 * 	  true - "боевой" режим (BLOCK). Режим в котором будут блокироваться все
 * обращения к скриптам которые отсутствуют в списке разрешенных. Внимание! При
 * переходе в этот режим не забудьте установить запрет на запись в данный файл
 * и в файл БД определенный в разделе конфигурация.
 */
define('PSS_STATUS_BLOCK', true);


/** ---------------------------- Конфигурация ------------------------------ **/
$pssConfig = array();

/* - Список допустимых IP администратора
 * Он имеет доступ ко всем скриптам вне зависимости от режима. Его действия не
 * будут влиять на стадии режима обучения.
 */
$pssConfig['admin_ip_list'] = array(
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
$pssConfig['admin_email'] = 'admin@site';

/* - Тип блокировки в режиме блокировки
 * 0 - не блокировать запросы (будет отсылаться только email на почту админа
 * если это разрешенно)
 * 1 - блокировать запросы и выводить сообщение о блокировке
 * 2 - блокировать запросы и выводить ошибку 403
 */
$pssConfig['block_type'] = 2;

/* - Высылать администратору письмо с уведомлением
 * Будет высылаться письмо уведомляющее администратора о попытке запуска
 * неразрешенных скриптов
 *
 * 0 - не высылать уведомление
 * 1 - высылать краткое описание события
 * 2 - высылать развернутое описание, включает в себя заголовки ответа и строку
 * пост запроса
 */
$pssConfig['alarm_block_send_email'] = 2;

/* - Уровень ошибок выводимых в браузер
 * Предупреждения будут выводится в браузер. Это может нарушить нормальную
 * работу сайтов.
 * 0 - отключить вывод ошибок
 * 1 - вывод критичных ошибок (Warning)
 * 2 - вывод критичных ошибок (Warning) и замечений (Notice)
 */
$pssConfig['alarm_html_level'] = 2;

/* - Вывод ошибок в браузер только для админа
 * Ошибки и предупреждения будут демонстрироваться только администратору
 * определенному по его IP адресу
 */
$pssConfig['alarm_html_only_admin'] = true;

/* - Файл БД
 * Файл в котором будут хранится данные о допустимых скриптах. В режиме обучения
 * необходим доступ на запись. В боевом режиме запись должна быть запрещенна.
 */
$pssConfig['file_data'] = 'data.txt';


/** ---------------------- Дополнительные параметры ------------------------ **/
/* * Внимание! При изменении параметров в данном разделе необходимо заново
 * создать базу данных с нуля */

/* - Способ подсчета контрольной суммы
 * Допустимо: crc, md5, sha
 */
$pssConfig['control_crc_method'] = 'md5';

/* - Контролировать имя домена
 * Включить ведение разных логов для разных доменов
 */
$pssConfig['path_control_domain'] = true;

/* - Контролировать номер порта
 * Включить ведение разных логов для разных локальных портов
 */
$pssConfig['path_control_port'] = false;

/* - Нормализация имени домена
 * При включении данной директивы будет удален начальный поддомен "www." из имени
 * домена
 */
$pssConfig['path_strip_domain'] = true;


/** -------------------------- Основной класс ------------------------------ **/
class PssMain{

	const
		STATUS_STUDY = false;
	const
		STATUS_BLOCK = true;
	const
		ERROR_NOTICE = 1;
	const
		ERROR_WARNING = 2;
	const
		FILE_DATA_SEPARATOR = '|';

	/** Метод работы скрипта (блокировать/обучаться)
	 * @var boolean */
	private $status = self::STATUS_STUDY;

	/** Набор с конфигурацией работы скрипта
	 * @var array */
	private $config = array();

	/** Статус запуска класса (true - класс запущен, false - произошли ошибки)
	 * @var boolean */
	private $inited = false;

	/** База данных с индетификаторами разрешенных файлов
	 * @var array */
	private $fileData = array();

	/** Флаг изменения база данных
	 * @var boolean */
	private $fileDataChanged = false;

	function __construct($isStatusBlock, $configArray)
	{
		$this->inited = false;

		if (!is_array($configArray)) {
			trigger_error(__METHOD__ . ': input var "$config_array" must be an array', E_USER_WARNING);
			return false;
		}

		if (!is_scalar($isStatusBlock)) {
			trigger_error(__METHOD__ . ': input var "$is_status_block" must be a scalar', E_USER_WARNING);
			return false;
		}

		$this->config = $configArray;

		if ($isStatusBlock) {
			$this->status = self::STATUS_BLOCK;
		} else {
			$this->status = self::STATUS_STUDY;
		}

		$this->inited = true;
	}

	/** Имеет ли пользователь статус админа
	 *
	 * @return boolean
	 */
	protected function isAdmin()
	{
		if (isset($_SERVER['REMOTE_ADDR']) && !empty($_SERVER['REMOTE_ADDR'])) {
			$ipList = $this->getConfig('admin_ip_list');

			$ipUser = $_SERVER['REMOTE_ADDR'];

			foreach ($ipList as $ip) {
				$ip = trim($ip);
				if (empty($ip)) continue;

				$tmp = explode('.', $ip);

				$pattern = array_fill(0, 4, '[0-9]{1,3}');

				for ($i = 0; ($i < count($tmp) && $i < 4); $i++) {
					if (is_numeric($tmp[$i])) {
						$pattern[$i] = $tmp[$i];
					}
				}

				if (preg_match('#^' . implode('\.', $pattern) . '$#', $ipUser)) {
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
	function process()
	{
		if (!$this->inited) {
			return false;
		}

		if (!$this->processBDLoad()) {
			return false;
		}

		if (!$this->isAdmin()) {
			$pageHash = $this->getFileHash();

			if ($this->getStatus() == self::STATUS_BLOCK) {
				$this->processStatusBlock($pageHash);
			} elseif ($this->getStatus() == self::STATUS_STUDY) {
				$this->processStatusStudy($pageHash);
			}
		}

		if (!$this->processBDSave()) {
			return false;
		}
	}

	/** Режим обучения
	 *
	 * @param string $pageHash
	 */
	protected function processStatusStudy($pageHash)
	{
		if (!$this->processBDExists($pageHash)) {
			$this->processBDAdd($pageHash);
		}
	}

	/** Режим блокирования
	 *
	 * @param string $pageHash
	 */
	protected function processStatusBlock($pageHash)
	{
		if ($this->processBDExists($pageHash) || $this->isAdmin()) {
			return true;
		}

		if ($this->getConfig('block_type') == 1) {
			$this->printBlock();
		} elseif ($this->getConfig('block_type') == 2) {
			$this->printForbidden();
		}

		if ($this->getConfig('alarm_block_send_email') > 0 && strlen($this->getConfig('admin_email')) > 0) {
			$this->sendAdminEmail();
		}

		if ($this->getConfig('block_type') > 0) {
			die();
		}
	}

	/** Добавляем новую запись в базу
	 *
	 * @param string $newHash
	 * @return boolean
	 */
	protected function processBDAdd($newHash)
	{
		if (!$this->processBDExists($newHash)) {
			$this->fileData[] = $newHash;
			$this->fileDataChanged = true;
		} else {
			return true;
		}
	}

	/** Проверка существования записи в базе
	 *
	 * @param string $hash
	 * @return boolean
	 */
	protected function processBDExists($hash)
	{
		return in_array($hash, $this->fileData);
	}

	/** Проверка файла БД
	 *
	 * @return boolean
	 */
	protected function processBDLoad()
	{
		$pathDataFile = dirname(__FILE__) . DIRECTORY_SEPARATOR . $this->getConfig('file_data');

		if (!file_exists($pathDataFile)) {
			$this->printError('Файл базы не найден!', self::ERROR_WARNING);
			return false;
		}

		if (!is_readable($pathDataFile)) {
			$this->printError('Файл базы не доступен для чтения', self::ERROR_WARNING);
			return false;
		}

		if ($this->getStatus() == self::STATUS_BLOCK) {
			if (is_writable($pathDataFile)) {
				$this->printError('Файл базы доступен для записи.' . "\n" . 'Запретите запись в файл базы!', self::ERROR_NOTICE);
			}
		} else {
			if (!is_writable($pathDataFile)) {
				$this->printError('Файл базы не доступен для записи в обучающем режиме.' . "\n" . 'Разрешите запись в файл базы!', self::ERROR_NOTICE);
			}
		}

		$dataString = @file_get_contents($pathDataFile);
		$dataString = trim($dataString);

		if (strlen($dataString) > 0) {
			$this->fileData = explode(self::FILE_DATA_SEPARATOR, $dataString);
		}

		if ($this->getStatus() == self::STATUS_BLOCK) {
			if (count($this->fileData) == 0) {
				$this->printError('Файл базы данных пуст (нет ни одного разрешенного скрипта)', self::ERROR_NOTICE);
			}
		}

		return true;
	}

	/** Запись изменений в базу
	 *
	 */
	protected function processBDSave()
	{
		if ($this->fileDataChanged) {
			$pathDataFile = dirname(__FILE__) . '/' . $this->getConfig('file_data');

			if (is_writable($pathDataFile)) {
				$dataString = implode(self::FILE_DATA_SEPARATOR, $this->fileData);
				file_put_contents($pathDataFile, $dataString);

				return true;
			} else {
				return false;
			}
		}

		return true;
	}

	/** Отправка уведомления на администраторский email
	 *
	 */
	protected function sendAdminEmail()
	{
		$mailSubject = 'PSS: обращение к неразрешенной странице';

		$mailBody   = array();
		$mailBody[] = 'Дата: ' . date('d.m.Y H:i:s');
		$mailBody[] = 'Ip адрес пользователя: ' . $_SERVER['REMOTE_ADDR'];
		$mailBody[] = '--------------------------------------------';

		if (strlen($this->getFileStringDomain()) > 0) {
			$mailBody[] = 'Домен: ' . $this->getFileStringDomain();
		}

		if (!empty($_SERVER['REQUEST_URI'])) {
			$mailBody[] = 'Запрос: ' . $_SERVER['REQUEST_URI'];
		}

		if (strlen($this->getFileStringName()) > 0) {
			$mailBody[] = 'Файл: ' . $this->getFileStringName();
		}

		$mailBody[] = '--------------------------------------------';

		if ($this->getConfig('alarm_block_send_email') == 2) {
			//Подробный отчет
			if (!empty($_SERVER['REQUEST_METHOD'])) {
				$mailBody[] = 'Тип запроса: ' . $_SERVER['REQUEST_METHOD'];
			}

			$mailBody[] = '--------------------------------------------';

			//Получение заголовков пакета
			$headers = array();
			if (!function_exists('getallheaders')) {
				foreach ($_SERVER as $key => $value) {
					if (substr($key, 0, 5) == "HTTP_") {
						$key = str_replace(" ", "-", ucwords(strtolower(str_replace("_", " ", substr($key, 5)))));
						$headers[$key] = $value;
					}
				}
			} else {
				$headers = getallheaders();
			}

			if (count($headers) > 0) {
				$mailBody[] = 'Заголовки: ';
				$mailBody[] = '';

				foreach ($headers as $key => $value) {
					$tmp = $key . ': ' . $value;
					if (strlen($tmp) > 1024) {
						$tmp = substr($tmp, 0, 1024) . '[......]';
					}

					$mailBody[] = $tmp;
				}

				$mailBody[] = '--------------------------------------------';
			}

			if (!empty($_POST)) {
				$mailBody[] = 'Пост запрос: ';
				$mailBody[] = '';

				$tmp = array();
				foreach ($_POST as $key => $value) {
					$tmp[] = $key . '=' . urlencode($value);
				}

				$tmp = implode('&', $tmp);
				if (strlen($tmp) > 1024) {
					$tmp = substr($tmp, 0, 1024) . '[......]';
				}

				$mailBody[] = $tmp;
				$mailBody[] = '--------------------------------------------';
			}
		}

		if ($this->getConfig('block_type') > 0) {
			$mailBody[] = 'Запрос заблокирован. Высланно данное уведомление.';
		} else {
			$mailBody[] = 'Запрос не был заблокирован согласно конфигурации. Высланно данное уведомление.';
		}

		//Письмо отсылаем в кодировке UTF-8
		$mail_headers = array(
			'MIME-Version: 1.0',
			'Content-Type: text/plain; charset="UTF-8";'
		);

		$mailSubject = '=?UTF-8?B?' . base64_encode($mailSubject) . '?=';

		@mail($this->getConfig('admin_email'), $mailSubject, implode("\r\n", $mailBody), implode("\n", $mail_headers));
	}

	/** Вывод ошибки в браузер
	 *
	 * @param string $errorMessage
	 * @param integer $errorLevel
	 */
	protected function printError($errorMessage, $errorLevel = self::ERROR_NOTICE)
	{
		if ($this->getConfig('alarm_html_only_admin') && !$this->isAdmin()) {
			return true;
		}

		if ($errorLevel > $this->getConfig('alarm_html_level')) {
			return true;
		}

		switch ($errorLevel) {
			case self::ERROR_NOTICE:
				$errorTitle = 'Внимание!';
				break;

			case self::ERROR_WARNING:
				$errorTitle = 'Критическая ошибка!';
				break;
		}

		$errorMessage	 = 'Php Prepend Security System' . '\n\n' . htmlspecialchars($errorTitle) . '\n' . htmlspecialchars($errorMessage) . '\n\n' . htmlspecialchars('PSS (c) InSys 2013');
		$errorMessage	 = str_replace("\r", '\n', $errorMessage);
		$errorMessage	 = str_replace("\n", '\n', $errorMessage);

		echo('<script>alert("' . $errorMessage . '");</script>');
	}

	/** Вывод ошибки в браузер
	 *
	 * @param string $error_message
	 * @param integer $error_level
	 */
	protected function printBlock()
	{
		echo('Sorry, access to this page is blocked by PSS');
	}

	/** Вывод ошибки в браузер
	 *
	 */
	protected function printForbidden()
	{
		if (!isset($_SERVER['SERVER_SIGNATURE']) || empty($_SERVER['SERVER_SIGNATURE'])) {
			$_SERVER['SERVER_SIGNATURE'] = 'Apache/2.2.4 (FreeBSD) mod_ssl/2.2.4 OpenSSL/0.9.8d PHP/5.2.4 Server at ' . ((!empty($_SERVER['HTTP_HOST'])) ? empty($_SERVER['HTTP_HOST']) : 'localhost') . ' Port ' . ((!empty($_SERVER['SERVER_PORT'])) ? empty($_SERVER['SERVER_PORT']) : '80');
		}

		if (!headers_sent()) {
			header("HTTP/1.0 403 Forbidden");
			header("HTTP/1.1 403 Forbidden");
			header("Status: 403 Forbidden");
		}

		echo('<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don\'t have permission to access ' . ((!empty($_SERVER['SCRIPT_NAME'])) ? $_SERVER['SCRIPT_NAME'] : 'this page') . ' on this server.</p>
<hr>
<address>' . $_SERVER['SERVER_SIGNATURE'] . '</address>
</body></html>');
	}

	/** Получить значение из конфига
	 *
	 * @param array $conf_section_name
	 * @return mixed
	 */
	protected function getConfig($conf_section_name)
	{
		if (!is_scalar($conf_section_name)) {
			trigger_error(__METHOD__ . ': input var "$conf_section_name" must be a scalar', E_USER_WARNING);
			return false;
		}

		if (array_key_exists($conf_section_name, $this->config)) {
			return $this->config[$conf_section_name];
		} else {
			trigger_error(__METHOD__ . ': undefined config section index: ' . htmlspecialchars($conf_section_name), E_USER_NOTICE);
			return false;
		}
	}

	/** Режим работы скрипта (блокирование - true, обучение - false)
	 *
	 * @return boolean
	 */
	protected function getStatus()
	{
		return $this->status;
	}

	/** Получить хеш сумму (индетификатор) запущенного скрипта
	 *
	 * @return string
	 */
	protected function getFileHash()
	{
		$hashFunc = 'md5';

		switch (strtolower($this->getConfig('control_crc_method'))) {
			case 'crc':
			case 'crc32':
				$hashFunc = 'crc32';
				break;

			case 'md5':
				$hashFunc = 'md5';
				break;

			case 'sha':
			case 'sha1':
				$hashFunc = 'sha1';
				break;

			default:
				$hashFunc = 'md5';
				break;
		}

		$fileString = $this->getFileString();

		if (function_exists($hashFunc) && is_callable($hashFunc)) {
			$result = $hashFunc($fileString);
		} else {
			trigger_error(__METHOD__ . ': unknown hash function: ' . htmlspecialchars($conf_section_name), E_USER_NOTICE);
			$result = base64_encode($fileString);
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
	protected function getFileString()
	{
		$result = array();

		if ($this->getConfig('path_control_domain')) {
			$result[] = (string)$this->getFileStringDomain();
		}

		if ($this->getConfig('path_control_port')) {
			$result[] = (string)$this->getFileStringPort();
		}

		$result[] = (string)$this->getFileStringName();

		return implode(':', $result);
	}

	/** Получить имя запрошенного файла
	 *
	 * @return string
	 */
	private function getFileStringName()
	{
		if (isset($_SERVER['SCRIPT_NAME']) && !empty($_SERVER['SCRIPT_NAME'])) {
			$result = $_SERVER['SCRIPT_NAME'];
		} elseif (isset($_SERVER['SCRIPT_FILENAME']) && !empty($_SERVER['SCRIPT_FILENAME'])) {
			$result = $_SERVER['SCRIPT_FILENAME'];
		} else {
			$result = '';
		}

		$result	 = str_replace('\\', '/', $result);
		$result	 = preg_replace('#/+#', '/', $result);
		$result	 = trim($result, '/');

		$result = strtolower($result);

		return $result;
	}

	/** Получить имя запрошенного домена
	 *
	 * @return string
	 */
	private function getFileStringDomain()
	{
		$result = '';

		if (isset($_SERVER['HTTP_HOST']) && !empty($_SERVER['HTTP_HOST'])) {
			$result = $_SERVER['HTTP_HOST'];
		} elseif (isset($_SERVER['SERVER_NAME']) && !empty($_SERVER['SERVER_NAME'])) {
			$result = $_SERVER['SERVER_NAME'];
		} elseif (isset($_SERVER['SERVER_ADDR']) && !empty($_SERVER['SERVER_ADDR'])) {
			$result = $_SERVER['SERVER_ADDR'];
		} else {
			$result = '';
		}

		$result = strtolower($result);

		if ($this->getConfig('path_strip_domain')) {
			$result = preg_replace('#^www\.#i', '', $result);
		}

		return $result;
	}

	/** Получить номер запрошенного порта
	 *
	 * @return string
	 */
	private function getFileStringPort()
	{
		$result = '';

		if (isset($_SERVER['SERVER_PORT']) && !empty($_SERVER['SERVER_PORT'])) {
			$result = $_SERVER['SERVER_PORT'];
		} else {
			$result = '80';
		}

		return $result;
	}

}

/** --------------------------- Тело скрипта ------------------------------- **/
//Инициализируем и запускаем основной класс
$pssClass = new PssMain(PSS_STATUS_BLOCK, $pssConfig);
$pssClass->process();

//Не засоряем глобальное пространство
unset($pssClass, $pssConfig);
