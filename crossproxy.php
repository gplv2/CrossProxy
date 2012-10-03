<?php
/**
 * LICENSE
 *
 * This source file is subject to the new BSD license that is bundled
 * with this package in the file LICENSE.txt.
 */

ini_set("zlib.output_compression", 'On');
ini_set("zlib.output_compression_level", -1);

$proxy = new CrossProxy(array('http://live.synctrace.com','dev/class.planning.php'));

class CrossProxy {

   const POST    = 'POST';
   const GET     = 'GET';
   const PUT     = 'PUT';
   const DELETE  = 'DELETE';

   /* Some presets */ 
   protected $settings= array(
      'curl_connecttimeout' => '5',
      'curl_connecttimeout_ms' => '5000',
      'debug' => 1,
      'verbose' => 5,
      'logfile' => 'proxy.log',
      'user_agent_string' => 'ByteConsult proxy user-agent'
   );

   /* Store unprocessed $_REQUEST , kind of a misleading name imho , but makes sense in terms of POST/GET etc */
   protected $_post_get = NULL;
   /* Store unprocessed $_SERVER */
   protected $_server = NULL;
   /* Store semi processed request headers works: (nginx / apache) */
   protected $_request_headers        = NULL;
   /* Store unprocessed request cookie from $_COOKIE : (nginx / apache) */
   protected $_request_cookie        = NULL;

   /* Will hold the processed host info where proxy requests will be forwarded to (user option)*/
   protected $_target_host       = NULL;
   /* Will hold the target url path which will be added to this request (user option)*/
   protected $_target_path       = NULL;

   /* Will hold processed full target url */
   protected $_target_url       = NULL;

   /* Now use the power of curl_info for the backend headers */
   protected $_backend_curl_info = NULL;
   protected $_backend_output = NULL;

   /* Will hold the response body/header sent back by the server that the proxy request was made to */
   protected $_backend_response_body      = NULL;
   protected $_backend_response_headers   = NULL;

   protected $_debug        = NULL;
   protected $_verbose      = 0;

   private   $fp_logfile    = NULL;

   public function  __construct( $forward_host, $allowed_hostnames = NULL, $handle_errors = FALSE, $conf_settings=array()) {

      if($handle_errors) {
         $this->_setErrorHandlers();
      }

      /* Check for cURL. period. the rest blows up */
      if(!function_exists('curl_init')) {
         header("HTTP/1.1 400 Bad Request"); 
         throw new Exception("Installing php5-curl first works better");
         die();
      }

      // Merge the class defaults with the settings
      if (!empty($conf_settings)) {
         $this->settings = array_merge($this->settings, $conf_settings);
      }

      if (!empty($this->settings['debug'])) {
         $this->_debug=1;
      }

      if (!empty($this->settings['verbose'])) {
         $this->_verbose=$this->settings['verbose'];
      }

      if (!empty($this->settings['logfile'])) {
         if (!empty($this->_debug)) { $this->trace(5,sprintf("%s - %s : %s", __METHOD__ , 'Opening log file', $this->settings['logfile'])); } 

         $this->fp_logfile = fopen($this->settings['logfile'], 'w+');
         if (!is_resource($this->fp_logfile)) {
            trigger_error('log file write problem'); exit;
         }
      }

      if (!empty($this->_debug)) { $this->trace(5,sprintf("%s - %s", __METHOD__ , 'Start, Parsing target host info')); } 
      /* Parse the forward host option */
      if (is_array($forward_host)) {
         list($this->_target_host, $this->_target_path )= array_values($forward_host);
      } else {
         $this->_target_host = $forward_host;
      }

      /* Parse the allowed hostnames */
      if($allowed_hostnames !== NULL) {
         if(is_array($allowed_hostnames)) {
            $this->_allowed_hostnames = $allowed_hostnames;
         } else {
            $this->_allowed_hostnames[] =$allowed_hostnames;
         }
      }

      /* Store the SERVER method since we will tailor it */
      // if (!empty($this->_debug)) { $this->trace(5,sprintf("%s - %s", __METHOD__ , 'Parsing _SERVER var info')); } 
      if(is_array($_SERVER)) {
         $this->_server = $_SERVER;
      } else {
         header("HTTP/1.1 403 Forbidden");
         throw new Exception("Empty server vars look very suspicious");
         die();
      }

      if (!empty($this->_debug)) { $this->trace(4, sprintf("%s - %s", __METHOD__ , '$_SERVER information')); }
      if (!empty($this->_debug)) { $this->trace(5, sprintf("%s - %s", __METHOD__ , print_r($this->_server,true))); }

      /* Store the REQUEST info since we will tailor it */
      if(is_array($_REQUEST)) {
         //print_r($_REQUEST); exit;
         $this->_post_get = $_REQUEST;
      } else {
         $this->_post_get = array();
      }

      if (!empty($this->_debug)) { $this->trace(4, sprintf("%s - %s", __METHOD__ , '$_REQUEST information')); }
      if (!empty($this->_debug)) { $this->trace(5, sprintf("%s - %s", __METHOD__ , print_r($this->_post_get,true))); }

      /* We can't live without 'real' user agents strings */
      if(!$this->get_srv_key('HTTP_USER_AGENT')) {
         header("HTTP/1.1 403 Forbidden");
         throw new Exception("No HTTP User Agent was found, we deny this client");
         die();
      }

      /* get cookies */
      if ($this->get_srv_key('HTTP_COOKIE')) {
         // $this->_request_cookies = $_COOKIE; // Better is SRV HTTP_COOKIE
         $this->_request_cookies = $this->get_srv_key('HTTP_COOKIE');
      }

      if (!empty($this->_debug)) { $this->trace(5, sprintf("%s - %s : %s", __METHOD__ , 'COOKIE information', $this->_request_cookies)); }

      /* Starting from version 5.4.0 , php-fastcgi will support the getallheaders function 
       * $phpVersion = phpversion();
       * if (function_exists("version_compare") && version_compare($phpVersion, "5.4.0",'<')) {
       *     // I support this for nginx/phpfpm
       * } 
       */

      /* Store the request headers From the request */
      /* for older php-fastcgi nginx support */
      if (!function_exists('getallheaders')) {
         foreach ($this->_server as $name => $value) {
            /* RFC2616 (HTTP/1.1) defines header fields as case-insensitive entities. */
            if (strtolower(substr($name, 0, 5)) == 'http_') {
               $headers[str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))))] = $value;
            }
         }
         $this->_request_headers=$headers;
      } else {
         /* for apache support */
         $this->_request_headers = getallheaders();
      }
      if (!empty($this->_debug)) { $this->trace(5, sprintf("%s - %s", __METHOD__ , 'Request header information')); }
      if (!empty($this->_debug)) { $this->trace(5, sprintf("%s - %s", __METHOD__ , print_r($this->_request_headers,true))); }

      if ($this->get_req_key('Accept-Encoding')) {
         unset($_request_headers['Accept-Encoding']);
      }

      if($this->_request_headers === FALSE) {
         header("HTTP/1.1 412 Precondition Failed"); 
         throw new Exception("Could not get request headers");
         die();
      }

      if (!$this->get_srv_key('REQUEST_METHOD')) {
         header("HTTP/1.1 405 Method Not Allowed");
         throw new Exception("Request method unknown or empty");
         die();
      }

      $method = strtoupper($this->get_srv_key('REQUEST_METHOD'));

      if(!in_array($method, array(self::GET, self::PUT, self::DELETE, self::POST))) {
         header(sprintf("HTTP/1.1 405 Method Not Allowed (%s)",$method));
         throw new Exception("Request method ($method) invalid");
         die();
      }
      $this->_request_method=$method;

      if (!empty($this->_debug)) { $this->trace(5, sprintf("%s - %s : %s", __METHOD__ , 'Incomming request method', $this->_request_method)); }

      if($this->_request_method === self::POST || $this->_request_method === self::PUT) {
         if (!empty($this->_debug)) { $this->trace(5, sprintf("%s - Reading %s php input", __METHOD__ , $this->_request_method)); }
         $this->_request_body = @file_get_contents('php://input');
      }

      if (!$this->get_req_key('Content-Type')) {
         $this->_request_content_type = $this->get_req_key('Content-Type');
      }

      $this->execute();

   }

   private function get_req_key($name) {
      if(key_exists($name, $this->_post_get)) {
         return($this->_post_get[$name]);
      } else {
         return null;
      }
   }

   private function get_hdr_key($name) {
      if(key_exists($name, $this->_request_headers)) {
         return($this->_request_headers[$name]);
      } else {
         return null;
      }
   }

   private function get_srv_key($name) {
      if(key_exists($name, $this->_server)) {
         return($this->_server[$name]);
      } else {
         return null;
      }
   }


   /**
    * Execute the proxy request. This method sets HTTP headers and write to the
    *  output stream. Make sure that no whitespace or headers have already been
    *  sent.
    */
   protected function execute() {
      if (!empty($this->_debug)) { $this->trace(3, sprintf("%s - %s", __METHOD__ , 'Validating user permissions...')); }
      $this->_validate_user_permissions();
      if (!empty($this->_debug)) { $this->trace(3, sprintf("%s - %s", __METHOD__ , 'Prepare the backend request..')); }
      $this->_create_request();
      if (!empty($this->_debug)) { $this->trace(3, sprintf("%s - %s", __METHOD__ , 'Perform request.')); }
      $this->_do_request();
      if (!empty($this->_debug)) { $this->trace(3, sprintf("%s - %s", __METHOD__ , 'Proxy Reply to client')); }
      $this->_send_reply();
      if (!empty($this->_debug)) { $this->trace(3, sprintf("%s - %s", __METHOD__ , 'Done')); }
   }

   /**
    * Check that the proxy request is coming from the appropriate host
    *  that was set in the second argument of the constructor
    * @return void
    * @throws Exception when a client hostname is not permitted on a request
    */
   protected function _validate_user_permissions() {

      if($this->_allowed_hostnames === NULL) {
         return;
      }

      if (!empty($this->_debug)) { $this->trace(3, sprintf("%s - %s", __METHOD__ , 'Validating request source.')); }
      $host=array();
      /* Validate the request source */
      if ($this->get_srv_key('REMOTE_HOST')) {
         $host = $this->get_srv_key('REMOTE_HOST');
      } elseif ($this->get_srv_key('REMOTE_ADDR')) {
         $host = $this->get_srv_key('REMOTE_ADDR');
      } else {

         if (!empty($host)) {
            if(!in_array($host, $this->_allowed_hostnames))
               if (!empty($this->_debug)) { $this->trace(3, sprintf("%s - %s", __METHOD__ , 'Access denied')); }
               header("HTTP/1.1 403 Forbidden");
            throw new Exception("Requests from hostname ($host) are not allowed");
            die();
         }
      }
   }

   /**
    * Make the proxy request using the supplied route and the base host we got
    *  in the constructor. Store the response in _raw_response
    */
   protected function _create_request() { 

      $url = $this->_target_host;

      if (isset($this->_target_path)) {
         $url = sprintf("%s/%s",$url, $this->_target_path);
      }

      /* GET support, it's easy when just piping along the encoded source qry string */
      if($this->_request_method === self::GET) {
         if ($this->get_srv_key('QUERY_STRING')) {
            $url = sprintf("%s?%s",$url, $this->get_srv_key('QUERY_STRING'));
         }
      }

      if (!empty($this->_debug)) { $this->trace(3, sprintf("%s - result: %s", __METHOD__ , $url)); }

      $this->_target_url = $url;
   }

   /**
    * Given the object's current settings, make a request to the given url
    *  using the cURL library
    * @param string $url The url to make the request to
    * @return string The full HTTP response
    */
   protected function _do_request() {
      $ch = curl_init($this->_target_url);
      $fh=null;

      /* POST */
      if (!empty($this->_debug)) { $this->trace(3, sprintf("%s - set curl %s options", __METHOD__ , $this->_request_method)); }

      if($this->_request_method === self::POST) {
         curl_setopt($ch, CURLOPT_POST, true);
         curl_setopt($ch, CURLOPT_ENCODING, "");
         curl_setopt($ch, CURLOPT_POSTFIELDS, $this->_request_body);
      } elseif($this->_request_method === self::PUT) {

         /* PUT */
         /** 
          * Great article on making PUT and delete work:
          * http://stackoverflow.com/questions/2153650/how-to-start-a-get-post-put-delete-request-and-judge-request-type-in-php
          */

         $fh = fopen('php://memory', 'rw');

         $requestLength = strlen($this->_request_body);

         fwrite($fh, $this->_request_body);
         rewind($fh);

         curl_setopt($ch, CURLOPT_PUT, true);
         curl_setopt($ch, CURLOPT_INFILE, $fh);
         curl_setopt($ch, CURLOPT_INFILESIZE, $requestLength);
         if (is_resource($fh)) {
            fclose($fh);
         }
      } elseif($this->_request_method === self::DELETE) {
         /* DELETE */
         curl_setopt($ch, CURLOPT_CUSTOMREQUEST, self::DELETE);
      } else {
         curl_setopt($ch, CURLOPT_CUSTOMREQUEST, self::GET);
      }

      /* TRUE to include the header in the output. */
      curl_setopt($ch, CURLOPT_HEADER, true);
      /* TRUE to include the sent header in the curl_info output, great debug aid */
      curl_setopt($ch, CURLINFO_HEADER_OUT, true);

      curl_setopt($ch, CURLOPT_USERAGENT, $this->get_srv_key('HTTP_USER_AGENT'));

      /* TRUE to return the transfer as a string of the return value of curl_exec() instead of outputting it out directly. */
      curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

      if ($this->get_req_key('Cookie')) {
         curl_setopt($ch, CURLOPT_COOKIE, $this->get_req_key('Cookie'));
      }

      /* We accept compressed input from the backend */ 
      //curl_setopt($ch, CURLOPT_HTTPHEADER, array('Accept-Encoding: gzip'));

      /* An array of HTTP header fields to set, in the format array('Content-type: text/plain', 'Content-length: 100') */
      // FIXME // curl_setopt($ch, CURLOPT_HTTPHEADER, $this->_generateProxyRequestHeaders());

/*
     // Accept: 
      curl_setopt($this->ch, CURLOPT_HTTPHEADER, array('HTTP_ACCEPT_LANGUAGE: UTF-8', 'ACCEPT: application/json'));
 */

      if (isset($this->settings['curl_connecttimeout'])) {
         curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $this->settings['curl_connecttimeout']);
      }

      if (isset($this->settings['curl_connecttimeout_ms'])) {
         curl_setopt($ch, CURLOPT_CONNECTTIMEOUT_MS, $this->settings['curl_connecttimeout_ms']);
      }

      $this->_backend_output = curl_exec($ch);
      $this->_backend_curl_info = curl_getinfo($ch);

      if (!empty($this->_debug)) { $this->trace(4, sprintf("%s - curl_info output", __METHOD__), $this->_backend_curl_info); }

   }

   protected function _send_reply() {
      if (!$this->_backend_curl_info['http_code']==200) {
         /*
         if (preg_match("/utf-8/", strtolower($this->_backend_curl_info['content_type']), $matches)) {
            if (!empty($matches[0])) {
               $contents = utf8_encode($this->_backend_output);
            }
         } else {
            $contents = $this->_backend_output;
         }
          */

         // echo $this->_backend_output;
         //ob_end_flush();
      }
      list( $headers, $this->_backend_response_body) =  explode("\r\n\r\n", $this->_backend_output, 2);
      // Can also be done like this (but keeps the \r\n\r\n somewhere in the resultset):
      // $header=substr($result,0,curl_getinfo($ch,CURLINFO_HEADER_SIZE));
      // $body=substr($result,curl_getinfo($ch,CURLINFO_HEADER_SIZE));

      /* I don't like the pecl one ...
      if(function_exists('http_parse_headers')) {
         $this->_backend_response_headers = http_parse_headers($headers);
      }
      * */
      $this->_backend_response_headers = $this->custom_http_parse_headers($headers);

      if (!empty($this->_debug)) { $this->trace(4, sprintf("%s - backend headers", __METHOD__), $this->_backend_response_headers); }
      if (!empty($this->_debug)) { $this->trace(4, sprintf("%s - backend body", __METHOD__)); }
      if (!empty($this->_debug)) { $this->trace(4, sprintf("%s - \tlength: %s", __METHOD__, strlen($this->_backend_response_body))); }

      // header(sprintf("HTTP/1.1 %d %s",$this->_backend_curl_info['http_code'],$this->get_code_definition($this->_backend_curl_info['http_code'])));
      foreach($this->_backend_response_headers as $key => $header) {
         if (!is_array($header)) {
            header("$key: $header",true);
         } else {
            if (!in_array($key, array('Content-Encoding', 'Vary','Content-Length','Connection','Content-Type'))) {
               header(sprintf("%s: %s",$key, implode(', ',$header)),true);
            }
         }
      }
      /*
       */
      header("Glenn: washere",true);
      // var_dump(headers_list());
      // exit;
      if (isset($this->_backend_response_body)) {
         //echo $this->_backend_response_body;
         //die();
      }
   }

   protected function _setErrorHandlers() {
      set_error_handler(array($this, 'handleError'));
      set_exception_handler(array($this, 'handleException'));
   }

   /**
    * A callback method for PHP's set_error_handler function. Used to handle
    *  application-wide errors
    * @param int       $code
    * @param string    $message
    * @param string    $file
    * @param int       $line
    */
   public function handleError($code, $message, $file, $line) {
      // Be scarse on error info
      // $this->_sendFatalError("Fatal proxy Error: '$message' in $file:$line");
      $this->_sendFatalError("Fatal Error: '$message'");
   }

   /**
    * A callback method for PHP's set_exception_handler function. Used to
    *  handle application-wide exceptions.
    * @param Exception $exception The exception being thrown
    */
   public function handleException(Exception $exception)
      {
      $this->_sendFatalError("Fatal Exception: '" . $exception->getMessage());
      /*
       * I don't want to hand out line information to an end user
       . "' in "
       . $exception->getFile()
       . ":"
       . $exception->getLine());
       */
      }

   /**
    * Display a fatal error to the user. This will halt execution.
    * @param string $message
    */
   protected static function _sendFatalError($message) {
      die($message);
   }

/*
   // Include this function on your pages
   private function gzip_output() {

      global $HTTP_ACCEPT_ENCODING;

      if( headers_sent() ){
         $encoding = false;
      }elseif( strpos($HTTP_ACCEPT_ENCODING, 'x-gzip') !== false ){
         $encoding = 'x-gzip';
      }elseif( strpos($HTTP_ACCEPT_ENCODING,'gzip') !== false ){
         $encoding = 'gzip';
      }else{
         $encoding = false;
      }

      if( $encoding ){
         $contents = ob_get_contents();
         ob_end_clean();
         header('Content-Encoding: '.$encoding);
         print("\x1f\x8b\x08\x00\x00\x00\x00\x00");
         $size = strlen($contents);
         $contents = gzcompress($contents, 9);
         $contents = substr($contents, 0, $size);
         print($contents);
         exit();
      }else{
         ob_end_flush();
         exit();
      }
   }
 */
   private function get_code_definition($code) {
      // see http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html RFC2616
      // [Informational 1xx]
      $def=array(
         '100'=>'Continue',
         '101'=>'Switching Protocols',
         // [Successful 2xx]
         '200'=>'OK',
         '201'=>'Created',
         '202'=>'Accepted',
         '203'=>'Non-Authoritative Information',
         '204'=>'No Content',
         '205'=>'Reset Content',
         '206'=>'Partial Content',
         // [Redirection 3xx]
         '300'=>'Multiple Choices',
         '301'=>'Moved Permanently',
         '302'=>'Found',
         '303'=>'See Other',
         '304'=>'Not Modified',
         '305'=>'Use Proxy',
         '306'=>'Unused',
         '307'=>'Temporary Redirect',
         // [Client Error 4xx]
         '400'=>'Bad Request',
         '401'=>'Unauthorized',
         '402'=>'Payment Required',
         '403'=>'Forbidden',
         '404'=>'Not Found',
         '405'=>'Method Not Allowed',
         '406'=>'Not Acceptable',
         '407'=>'Proxy Authentication Required',
         '408'=>'Request Timeout',
         '409'=>'Conflict',
         '410'=>'Gone',
         '411'=>'Length Required',
         '412'=>'Precondition Failed',
         '413'=>'Request Entity Too Large',
         '414'=>'Request-URI Too Long',
         '415'=>'Unsupported Media Type',
         '416'=>'Requested Range Not Satisfiable',
         '417'=>'Expectation Failed',
         // [Server Error 5xx]
         '500'=>'Internal Server Error',
         '501'=>'Not Implemented',
         '502'=>'Bad Gateway',
         '503'=>'Service Unavailable',
         '504'=>'Gateway Timeout',
         '505'=>'HTTP Version Not Supported'
      );
   }


   private function custom_http_parse_headers( $header ) {
      $retVal = array();
      $fields = explode("\r\n", preg_replace('/\x0D\x0A[\x09\x20]+/', ' ', $header));
      foreach( $fields as $field ) {
         if( preg_match('/([^:]+): (.+)/m', $field, $match) ) {
            $match[1] = preg_replace('/(?<=^|[\x09\x20\x2D])./e', 'strtoupper("\0")', strtolower(trim($match[1])));
            if( isset($retVal[$match[1]]) ) {
               $retVal[$match[1]] = array($retVal[$match[1]], $match[2]);
            } else {
               $retVal[$match[1]] = trim($match[2]);
            }
         }
      }
      return $retVal;
   }

   private function trace($level, $msg) {
      if (empty($this->_debug) || empty($this->_verbose) || empty($level) || empty($msg)) { return; }

      $out_array = array ();
      $numargs = func_num_args();
      if ($numargs == 3) {
         $out_array = func_get_arg(2);
         if (!is_array($out_array)) {
            $out_array = array();
         }
      }

      $DateTime=@date('Y-m-d H:i:s', time());

      if ( $level <= $this->_verbose ) {
         $mylvl=NULL;
         switch($level) {
            case 0:
               $mylvl ="error";
               break;
            case 1:
               $mylvl ="core ";
               break;
            case 2:
               $mylvl ="info ";
               break;
            case 3:
               $mylvl ="notic";
               break;
            case 4:
               $mylvl ="verbs";
               break;
            case 5:
               $mylvl ="dtail";
               break;
            default :
               $mylvl ="exec ";
               break;
         }
         $content = $DateTime. " [" .  posix_getpid() ."]:[" . $level . "]" . $mylvl . " - " . $msg . "\n";
         if (count($out_array)) {
            foreach($out_array as $key => $val) {
               $content = $DateTime. " [" .  posix_getpid() ."]:[" . $level . "]" . $mylvl . " - " . $key ." => " . $val . "\n";
            }
         }
         if (is_resource($this->fp_logfile)) {
            fwrite($this->fp_logfile, $content);
         } else {
            echo $content;
         }
      }
   }

   public function __destruct() {
      if (is_resource($this->fp_logfile)) {
         fclose($this->fp_logfile);
      }
   }
}
?>
