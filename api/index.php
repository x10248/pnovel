<?php
error_reporting(0);
/*
 * 请勿使用windows下的记事本修改本文件。推荐使用 notepad++
 * 版本 v1.0.2
 * 升级日志：
 * 1、修正第一次无法打开，需要刷新才能打开的BUG
 * 2、添加对二级目录的支持
 * 3、添加对非index.php文件名的支持。
 * 4、修复代理请求头问题，增强反爬绕过能力
 * 对于开发环境：可以保持no-store方便调试
 * */
$appId = '8070';  // 站点的APPID （请勿修改）
$appKey = '1e7hohy6uosf9pbt8tzcng3fcxgqu1ywg6d4ncai03xat94123eqji6wgmma';// 站点的APP KEY（请勿修改）

// 调试模式
define('DEBUG', false);

//===============================================================================
//===============================================================================
//===============================================================================
//================               请勿修改以下程序            ====================
//===============================================================================
//===============================================================================
//===============================================================================

$host = "https://www.shuyous.com";
$localDomain = 'http://' . $_SERVER['HTTP_HOST'];

// Cookie管理器类
class CookieManager {
    private static $cookieFile;
    private static $initialized = false;
    
    public static function init() {
        self::$cookieFile = tempnam(sys_get_temp_dir(), 'shuyous_cookie_');
        
        // 初始化时先访问首页获取基础cookies
        if (!self::$initialized) {
            self::fetchHomepageCookies();
            self::$initialized = true;
        }
    }
    
    private static function fetchHomepageCookies() {
        $ch = curl_init("https://www.shuyous.com/");
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => true,
            CURLOPT_NOBODY => false,
            CURLOPT_COOKIEJAR => self::$cookieFile,
            CURLOPT_COOKIEFILE => self::$cookieFile,
            CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            CURLOPT_TIMEOUT => 10,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 3,
        ]);
        
        curl_exec($ch);
        curl_close($ch);
        
        if (DEBUG) {
            error_log("Initial cookies fetched and saved to: " . self::$cookieFile);
        }
    }
    
    public static function getCookieFile() {
        return self::$cookieFile;
    }
    
    public static function clean() {
        if (file_exists(self::$cookieFile)) {
            unlink(self::$cookieFile);
        }
        self::$initialized = false;
    }
}

// 初始化cookie管理器
CookieManager::init();

// 静态资源走 curl 代理，不缓存，不注入广告
// 静态资源部分修改
$ext = strtolower(pathinfo(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH), PATHINFO_EXTENSION));
$allow = ['css','js','png','jpg','jpeg','gif','ico','svg','woff','woff2','ttf','eot'];
if (in_array($ext, $allow, true)) {
    $remote = $host . $_SERVER['REQUEST_URI'];

    // 使用缓存
    $staticCache = new StaticCache(3600); // 服务器缓存1小时
    $cacheKey = md5($remote);

    if ($cached = $staticCache->get($cacheKey)) {
        $headers = $staticCache->getCacheHeaders($ext);
        foreach ($headers as $name => $value) {
            header($name . ': ' . $value);
        }
        echo $cached;
        exit;
    }

    // 从远程获取、处理、重写URL ...
    $ch = curl_init($remote);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_TIMEOUT        => 20,
        CURLOPT_USERAGENT      => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        CURLOPT_REFERER        => $host . '/',
        CURLOPT_COOKIEFILE     => CookieManager::getCookieFile(),
        CURLOPT_COOKIEJAR      => CookieManager::getCookieFile(),
        CURLOPT_ENCODING       => 'gzip, deflate', // 添加自动解压
    ]);
    
    $body = curl_exec($ch);
    $info = curl_getinfo($ch);
    
    // 检查是否需要手动解压
    if (isset($info['content_encoding']) && stripos($info['content_encoding'], 'gzip') !== false) {
        $decompressed = @gzdecode($body);
        if ($decompressed !== false) {
            $body = $decompressed;
        }
    }
    
    curl_close($ch);

    // 对CSS文件进行URL重写
    // 对JS文件进行URL重写
    if ($ext === 'css') {
        //$body = rewriteResourceUrls($body, $host, $localDomain, 'css');
    } elseif ($ext === 'js') {
        $body = rewriteResourceUrls($body, $host, $localDomain, 'js');
    }

    if ($info['http_code'] === 200 && strlen($body)) {
        // 保存到缓存
        $staticCache->set($cacheKey, $body);
        header('Content-Type: ' . ($info['content_type'] ?: 'application/octet-stream'));
        header('Cache-Control: no-store');
        echo $body;
    } else {
        http_response_code(404);
    }
    exit;
}

$requestMethod = strtoupper(@$_SERVER["REQUEST_METHOD"]);
$requestUrl = @$_SERVER["REQUEST_URI"];

$cache = new CacheHelper();

// 修改现有的清理功能
if (isset($_REQUEST['clean'])) {
    // 清理HTML缓存
    $cache->clean();
    
    // 清理Cookies
    CookieManager::clean();
    
    // 清理静态缓存
    $staticCache = new StaticCache();
    $staticCount = $staticCache->cleanAll();
    
    echo "已清除所有缓存和cookies\n";
    echo "清理了 {$staticCount} 个静态缓存文件";
    exit;
}
// 可以添加专门的静态缓存清理
if (isset($_REQUEST['clean_static'])) {
    $staticCache = new StaticCache();
    $count = $staticCache->cleanAll();
    echo "已清除 {$count} 个静态缓存文件";
    exit;
}

// 查看缓存统计
if (isset($_REQUEST['cache_stats'])) {
    $staticCache = new StaticCache();
    $stats = $staticCache->getStats();
    echo "<pre>";
    print_r($stats);
    echo "</pre>";
    exit;
}

$key = md5($requestUrl . CacheHelper::isMobile() . CacheHelper::isIPad() . CacheHelper::isIPhone() . CacheHelper::isMicroMessenger());
if ($requestMethod == 'GET') {
    $cacheData = $cache->Get($key);
    if ($cacheData !== false) {
        echo $cacheData;
        exit;
    }
}

$documentUrl = @$_SERVER["PHP_SELF"];
$httpHelper = new HttpHelper($appId, $appKey, $documentUrl);
$html = $httpHelper->getHtml($host, $requestUrl, $requestMethod == 'POST' ? @$_POST : array(), $requestMethod);

// 在此处添加URL重写, 在缓存之前进行URL重写, 只对文本文件进行重写：
$textExtensions = ['css', 'js', 'html', 'htm', 'xml', 'json', 'txt'];
if (in_array($ext, $textExtensions)) {
    //$html = rewriteResourceUrls($html, $host, $localDomain, $ext);
    // 方法1：使用增强的重写函数
    $html = rewriteAllContentUrls($html, $host, $localDomain); 
    // 或者方法2：使用DOM解析器（更精确但稍慢）
    /*
    if (class_exists('DOMDocument')) {
        //echo "DOMDocument";
        //exit;
        $html = rewriteUrlsWithDOM($html, $host, $localDomain);
    } else {
        $html = rewriteAllContentUrls($html, $host, $localDomain);
    }
    */
}

if ($requestMethod == 'GET' && !empty($html) && $httpHelper->getCacheBoolean()==1) {
    $cache->Set($key, $html, 60);
}

// 页面内容修改
/*
$htmllast = '<script type="text/javascript">'
          . 'jQuery(".conR .btnQS").append(\'<a href="/download.html" target="_blank" style="margin-left:10px;">资源下载</a>\');'
          . '</script></body>' . PHP_EOL . '</html>';
echo str_replace('</body>' . PHP_EOL . '</html>', $htmllast, $html);
*/
$htmllast = '
<script>
function tryInsert() {
    var $conR = $(".conR");
    if ($conR.length) {
        // 添加资源下载按钮
        $conR.append(\'<span style="margin-left:8px;"><a href="/download.html" target="_blank">资源下载</a></span>\');
        
        // 添加翻译占位div
        $conR.append(\'<div id="translate" style="display:inline-block; margin-left:8px; vertical-align:middle;"></div>\');
        return;
    }
    setTimeout(tryInsert, 300);
}
tryInsert();
</script>
<script src="https://cdn.staticfile.net/translate.js/3.5.1/translate.js"></script>
<script>
function tryInsert2() {
    var $div = $("#translate");
    if ($div.length) {
        translate.language.setLocal("chinese_simplified"); 
        translate.service.use("client.edge"); 
        translate.execute();
        return;
    }
    setTimeout(tryInsert2, 300);   // 每 300ms 重试一次
}
tryInsert2();
</script>
</body>' . PHP_EOL . '</html>';

echo preg_replace('~</body>\s*?</html>~i', $htmllast, $html);

class HttpHelper
{
    protected $appId;
    protected $key;
    protected $documentUrl;
    protected $cache_boolean;
    protected $cookieFile;

    public function __construct($appId, $key, $documentUrl)
    {
        $this->appId = $appId;
        $this->key = $key;
        $this->documentUrl = $documentUrl;
        $this->cookieFile = CookieManager::getCookieFile();
    }

    /**
     * @param $url
     * @param $requestUrl
     * @param array $param
     * @param string $method
     * @param bool $isAjax
     * @param string $cookie
     * @param string $refer
     * @param null $userAgent
     * @return string
     */
    public function getHtml($url, $requestUrl, $param = array(), $method = 'GET', $isAjax = null, $cookie = NULL, $refer = null, $userAgent = null)
    {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_HEADER, 1);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
        
        // 设置Referer
        if (empty($refer)) {
            if (strpos($requestUrl, '/book/') !== false) {
                $refer = $url . '/';
            } else {
                $refer = isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : $url . '/';
            }
        }
        
        // 设置User-Agent
        $ua = $userAgent ?: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
        curl_setopt($ch, CURLOPT_USERAGENT, $ua);
        curl_setopt($ch, CURLOPT_REFERER, $refer);
        
        // 基本curl设置
        curl_setopt($ch, CURLOPT_TIMEOUT, 20);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        
        // 重要：设置自动解压
        curl_setopt($ch, CURLOPT_ENCODING, 'gzip, deflate');
        
        // Cookie设置
        curl_setopt($ch, CURLOPT_COOKIEFILE, $this->cookieFile);
        curl_setopt($ch, CURLOPT_COOKIEJAR, $this->cookieFile);
        
        // 构建请求头 - 使用标准浏览器头部
        $header = array();
        
        // 从原始请求中传递部分标准头部
        $standardHeaders = ['Accept', 'Accept-Language', 'Content-Type', 'Content-Length'];
        foreach ($standardHeaders as $h) {
            $serverKey = 'HTTP_' . strtoupper(str_replace('-', '_', $h));
            if (isset($_SERVER[$serverKey]) && !empty($_SERVER[$serverKey])) {
                $header[] = $h . ': ' . $_SERVER[$serverKey];
            }
        }
        
        // 如果没有Accept头，设置默认值
        $hasAccept = false;
        foreach ($header as $h) {
            if (stripos($h, 'Accept:') === 0) {
                $hasAccept = true;
                break;
            }
        }
        
        if (!$hasAccept) {
            $header[] = 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9';
        }
        
        // 添加常见的浏览器头部
        $header[] = 'Connection: keep-alive';
        $header[] = 'Upgrade-Insecure-Requests: 1';
        $header[] = 'Sec-Fetch-Dest: document';
        $header[] = 'Sec-Fetch-Mode: navigate';
        $header[] = 'Sec-Fetch-Site: none';
        $header[] = 'Sec-Fetch-User: ?1';
        
        // 接受gzip编码
        $header[] = 'Accept-Encoding: gzip, deflate';
        
        // 传递客户端IP（如果需要）
        $clientIp = $this->get_real_ip();
        if (!empty($clientIp)) {
            $header[] = 'X-Forwarded-For: ' . $clientIp;
            $header[] = 'X-Real-IP: ' . $clientIp;
        }
        
        // 设置请求头
        curl_setopt($ch, CURLOPT_HTTPHEADER, $header);
        
        // 构建完整URL
        $fullUrl = $url . $requestUrl;
        
        // 处理POST请求
        if (strtolower($method) == 'post') {
            curl_setopt($ch, CURLOPT_POST, true);
            if ($param && is_array($param)) {
                curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($param));
            }
            curl_setopt($ch, CURLOPT_URL, $fullUrl);
        } else {
            // GET请求，添加参数
            if ($param && is_array($param)) {
                $urlInfo = parse_url($fullUrl);
                $query = [];
                if (isset($urlInfo['query'])) {
                    parse_str($urlInfo['query'], $query);
                }
                $query = array_merge($query, $param);
                
                $newUrl = (isset($urlInfo['scheme']) ? $urlInfo['scheme'] . '://' : '')
                        . (isset($urlInfo['host']) ? $urlInfo['host'] : '')
                        . (isset($urlInfo['port']) ? ':' . $urlInfo['port'] : '')
                        . (isset($urlInfo['path']) ? $urlInfo['path'] : '')
                        . (count($query) ? '?' . http_build_query($query) : '');
                curl_setopt($ch, CURLOPT_URL, $newUrl);
            } else {
                curl_setopt($ch, CURLOPT_URL, $fullUrl);
            }
        }
        
        if (DEBUG) {
            error_log("=== HTTP HELPER DEBUG ===");
            error_log("Request URL: " . curl_getinfo($ch, CURLOPT_URL));
            error_log("User-Agent: " . $ua);
            error_log("Referer: " . $refer);
            error_log("Cookie File: " . $this->cookieFile);
            error_log("Headers: " . print_r($header, true));
        }
        
        // 执行请求
        $r = curl_exec($ch);
        
        if (curl_errno($ch)) {
            if (DEBUG) {
                error_log("CURL Error: " . curl_error($ch));
            }
            curl_close($ch);
            http_response_code(500);
            echo "Proxy Error: " . curl_error($ch);
            exit;
        }
        
        $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $responseHeaders = mb_substr($r, 0, $headerSize);
        $body = mb_substr($r, $headerSize);
        $info = curl_getinfo($ch);
        
        if (DEBUG) {
            error_log("Response Code: " . $info['http_code']);
            error_log("Content-Encoding: " . ($info['content_encoding'] ?? 'none'));
            error_log("Response Headers Size: " . $headerSize);
            error_log("Response Body Size: " . strlen($body));
            error_log("Final URL: " . $info['url']);
        }
        
        curl_close($ch);
        
        // 处理响应头
        $headers = explode("\r\n", $responseHeaders);
        $location = null;
        $contentEncoding = null;
        $contentType = null;
        
        foreach ($headers as $h) {
            $h = trim($h);
            if (empty($h)) continue;
            
            // 检查内容编码
            if (stripos($h, 'Content-Encoding:') === 0) {
                $contentEncoding = trim(substr($h, 16));
                continue; // 不传递Content-Encoding头
            }
            
            // 检查内容类型
            if (stripos($h, 'Content-Type:') === 0) {
                $contentType = trim(substr($h, 13));
            }
            
            // 处理重定向
            if (stripos($h, 'Location:') === 0) {
                $location = substr($h, 9);
                header($h, false);
                continue;
            }
            
            // 过滤不需要传递的头部
            if (preg_match('/^(HTTP\/|Connection|Server|X-Powered-By|Date|Transfer-Encoding|EagleId)/i', $h)) {
                continue;
            }
            
            // 检查缓存头部
            if (preg_match('/^(CMS-CACHE)/i', $h)) {
                $this->cache_boolean = true;
            }
            
            // 传递其他头部（除了Set-Cookie）
            if (!preg_match('/^Set-Cookie:/i', $h)) {
                header($h);
            }
        }
        
        // 手动解压gzip内容（如果curl没有自动解压）
        if ($contentEncoding && stripos($contentEncoding, 'gzip') !== false) {
            if (DEBUG) {
                error_log("Detected gzip content, attempting decompression");
            }
            
            // 尝试解压gzip
            $decompressed = @gzdecode($body);
            if ($decompressed !== false) {
                $body = $decompressed;
                if (DEBUG) {
                    error_log("Successfully decompressed gzip content");
                }
            } else {
                // 如果gzdecode失败，尝试使用gzinflate（针对deflate）
                $decompressed = @gzinflate(substr($body, 10));
                if ($decompressed !== false) {
                    $body = $decompressed;
                    if (DEBUG) {
                        error_log("Successfully decompressed with gzinflate");
                    }
                } else {
                    if (DEBUG) {
                        error_log("Failed to decompress content, using raw");
                    }
                }
            }
            
            // 移除Content-Encoding头，因为我们已经解压了
            header_remove('Content-Encoding');
        }
        
        // 确保有正确的内容类型
        if (!$contentType && !headers_sent()) {
            header('Content-Type: text/html; charset=UTF-8');
        }
        
        // 处理重定向
        if ($info['http_code'] >= 300 && $info['http_code'] < 400 && $location) {
            http_response_code($info['http_code']);
            exit;
        }
        
        // 输出响应主体
        http_response_code($info['http_code']);
        
        if (DEBUG) {
            error_log("Body preview (first 200 chars): " . substr($body, 0, 200));
            error_log("=== END DEBUG ===\n");
        }
        
        return $body;
    }

    function get_real_ip()
    {
        $ip = '';
        $headers = [
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_FORWARDED',
            'HTTP_FORWARDED_FOR',
            'HTTP_FORWARDED',
            'HTTP_CLIENT_IP',
            'HTTP_X_CLUSTER_CLIENT_IP',
            'REMOTE_ADDR'
        ];
        
        foreach ($headers as $header) {
            if (!empty($_SERVER[$header])) {
                $ip = $_SERVER[$header];
                break;
            }
        }
        
        // 处理多个IP的情况（如经过代理）
        if (strpos($ip, ',') !== false) {
            $ips = explode(',', $ip);
            $ip = trim($ips[0]);
        }
        
        return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : $_SERVER['REMOTE_ADDR'];
    }

    public function getIsAjaxRequest()
    {
        return isset($_SERVER['HTTP_X_REQUESTED_WITH']) && $_SERVER['HTTP_X_REQUESTED_WITH'] === 'XMLHttpRequest';
    }

    public function getCacheBoolean()
    {
        return $this->cache_boolean;
    }
}

class CacheHelper
{
    protected $dir = '';

    public function __construct()
    {
        $this->dir = dirname(__FILE__) . DIRECTORY_SEPARATOR . 'cache';
        if (is_dir($this->dir)) {
            return;
        }
        @mkdir($this->dir, 0755, true);
    }

    public function Set($key, $value, $expire = 360)
    {
        $data = array(
            'time' => time(),
            'expire' => $expire,
            'value' => $value
        );
        @file_put_contents($this->dir . DIRECTORY_SEPARATOR . md5($key) . 'cache', serialize($data));
    }

    public function Get($key)
    {
        $file = $this->dir . DIRECTORY_SEPARATOR . md5($key) . 'cache';
        if (!file_exists($file)) {
            return false;
        }
        $str = @file_get_contents($file);
        if (empty($str)) {
            return false;
        }
        $data = @unserialize($str);
        if (!isset($data['time']) || !isset($data['expire']) || !isset($data['value'])) {
            return false;
        }
        if ($data['time'] + $data['expire'] < time()) {
            @unlink($file);
            return false;
        }
        return $data['value'];
    }

    static function isMobile()
    {
        $ua = @$_SERVER['HTTP_USER_AGENT'];
        return preg_match('/(iphone|android|Windows\sPhone)/i', $ua);
    }

    public function clean()
    {
        if (!empty($this->dir) && is_dir($this->dir)) {
            $files = scandir($this->dir);
            foreach ($files as $file) {
                if ($file !== '.' && $file !== '..') {
                    @unlink($this->dir . DIRECTORY_SEPARATOR . $file);
                }
            }
        }
    }

    static function isMicroMessenger()
    {
        $ua = @$_SERVER['HTTP_USER_AGENT'];
        return preg_match('/MicroMessenger/i', $ua);
    }

    static function isIPhone()
    {
        $ua = @$_SERVER['HTTP_USER_AGENT'];
        return preg_match('/iPhone/i', $ua);
    }

    static function isIPad()
    {
        $ua = @$_SERVER['HTTP_USER_AGENT'];
        return preg_match('/(iPad)/i', $ua);
    }
}

// 在代理文件的主逻辑部分添加：
//方案一：增强URL重写函数
// 在代理文件中添加或修改rewriteAllUrls函数
function rewriteAllUrls($content, $remoteDomain, $localDomain) {
    $remoteHost = parse_url($remoteDomain, PHP_URL_HOST);
    $localHost = parse_url($localDomain, PHP_URL_HOST) ?: $_SERVER['HTTP_HOST'];
    
    // 移除可能的空格和实体编码干扰
    $remoteHostPattern = preg_quote($remoteHost, '/');
    
    // 更全面的匹配模式
    $patterns = array(
        // 1. HTML标签属性中的URL（包含https://）
        '/(href|src|action|data-src|data-href|content)\s*=\s*["\']https?:\/\/' . $remoteHostPattern . '(\/[^"\']*)["\']/i',
        
        // 2. 纯文本中的完整URL（考虑前后的空格和实体编码）
        '/([^"\'>])(https?:\/\/' . $remoteHostPattern . '(\/[^\s<"\']*))/i',
        
        // 3. 协议相对URL
        '/(href|src|action|data-src|data-href|content)\s*=\s*["\']\/\/' . $remoteHostPattern . '(\/[^"\']*)["\']/i',
        
        // 4. 文本中的协议相对URL
        '/([^"\'>])(\/\/' . $remoteHostPattern . '(\/[^\s<"\']*))/i',
        
        // 5. 注释中的URL（需要特殊处理）
        '/(<!--.*?)(https?:\/\/' . $remoteHostPattern . '(\/[^\s<>"\']*))(.*?-->)/is',
        
        // 6. CDATA中的URL
        '/(<!\[CDATA\[.*?)(https?:\/\/' . $remoteHostPattern . '(\/[^\s<>"\']*))(.*?\]\]>)/is',
        
        // 7. 带有HTML实体编码的情况
        '/&nbsp;(https?:\/\/' . $remoteHostPattern . '(\/[^\s<"\']*))/i',
        '/(https?:\/\/' . $remoteHostPattern . '(\/[^\s<"\']*))&nbsp;/i',
    );
    
    $replacements = array(
        // 1. HTML属性
        '$1="' . $localDomain . '$2"',
        
        // 2. 纯文本URL
        '$1' . $localDomain . '$3',
        
        // 3. 协议相对属性
        '$1="' . $localDomain . '$2"',
        
        // 4. 协议相对文本
        '$1' . $localDomain . '$3',
        
        // 5. 注释中的URL
        '$1' . $localDomain . '$3$4',
        
        // 6. CDATA中的URL
        '$1' . $localDomain . '$3$4',
        
        // 7. 实体编码前后的URL
        '&nbsp;' . $localDomain . '$2',
        $localDomain . '$2&nbsp;',
    );
    
    // 多次替换以确保覆盖所有情况
    $content = preg_replace($patterns, $replacements, $content);
    
    // 额外处理：直接替换已知的域名格式
    $content = str_replace(
        [
            'http://www.shuyous.com',
            'https://www.shuyous.com',
            'http://shuyous.com',
            'https://shuyous.com',
            '//www.shuyous.com',
            '//shuyous.com',
        ],
        $localDomain,
        $content
    );
    
    return $content;
}
// 在使用时：
//$localDomain = 'http://' . $_SERVER['HTTP_HOST'];
//$html = rewriteAllUrls($html, $host, $localDomain);
//方案二：专门处理文本内容中的URL
function rewriteTextUrls($content, $remoteDomain, $localDomain) {
    $remoteHost = parse_url($remoteDomain, PHP_URL_HOST);
    $localHost = parse_url($localDomain, PHP_URL_HOST) ?: $_SERVER['HTTP_HOST'];
    
    // 专门处理纯文本中的URL（不在HTML标签属性中）
    // 使用更精确的正则匹配
    $pattern = '/(?<!["\'>])(https?:\/\/' . preg_quote($remoteHost, '/') . '\/[^\s<>"\']+)(?!["\'])/i';
    
    $content = preg_replace_callback($pattern, function($matches) use ($localDomain) {
        // 保持URL路径不变，只替换域名
        $path = parse_url($matches[1], PHP_URL_PATH);
        $query = parse_url($matches[1], PHP_URL_QUERY);
        $fragment = parse_url($matches[1], PHP_URL_FRAGMENT);
        
        $newUrl = $localDomain . $path;
        if ($query) $newUrl .= '?' . $query;
        if ($fragment) $newUrl .= '#' . $fragment;
        
        return $newUrl;
    }, $content);
    
    return $content;
}
//添加专门的注释处理
function rewriteUrlsInComments($content, $remoteDomain, $localDomain) {
    $remoteHost = parse_url($remoteDomain, PHP_URL_HOST);
    
    // 处理HTML注释中的URL
    $content = preg_replace_callback(
        '/<!--(.*?)-->/s',
        function($matches) use ($remoteHost, $localDomain) {
            $comment = $matches[1];
            // 替换注释中的URL
            $comment = preg_replace(
                '/(https?:\/\/)(?:www\.)?' . preg_quote($remoteHost, '/') . '(\/[^\s<>"\']*)/i',
                $localDomain . '$2',
                $comment
            );
            return '<!--' . $comment . '-->';
        },
        $content
    );
    
    return $content;
}
//使用更激进的正则
function rewriteAllUrlsAggressive($content, $remoteDomain, $localDomain) {
    $remoteHost = parse_url($remoteDomain, PHP_URL_HOST);
    $localHost = parse_url($localDomain, PHP_URL_HOST) ?: $_SERVER['HTTP_HOST'];
    
    // 匹配所有出现的域名（包含各种变体）
    $pattern = '/
        (?:https?:)?\/\/    # 可选的协议
        (?:www\.)?          # 可选的www
        ' . preg_quote($remoteHost, '/') . '  # 域名
        (?::\d+)?           # 可选的端口
        (\/[^\s<>"\']*)?    # 路径部分
    /ix';
    
    return preg_replace_callback($pattern, function($matches) use ($localDomain) {
        $fullMatch = $matches[0];
        
        // 如果是完整URL（包含协议）
        if (strpos($fullMatch, '//') === 0) {
            // 协议相对URL
            return $localDomain . (isset($matches[1]) ? $matches[1] : '');
        } elseif (strpos($fullMatch, 'http') === 0) {
            // 完整HTTP/HTTPS URL
            return $localDomain . (isset($matches[1]) ? $matches[1] : '');
        }
        
        return $fullMatch;
    }, $content);
}
//使用两步替换法
function rewriteUrlsTwoStep($content, $remoteDomain, $localDomain) {
    $remoteHost = parse_url($remoteDomain, PHP_URL_HOST);
    
    // 第一步：处理所有明显的URL格式
    $patterns = [
        // 完整URL
        '/(https?:\/\/)(?:www\.)?' . preg_quote($remoteHost, '/') . '(\/[^\s<>"\']*)/i',
        // 协议相对
        '/(\/\/)(?:www\.)?' . preg_quote($remoteHost, '/') . '(\/[^\s<>"\']*)/i',
    ];
    
    foreach ($patterns as $pattern) {
        $content = preg_replace($pattern, $localDomain . '$2', $content);
    }
    
    // 第二步：处理特殊情况（在文本中）
    $specialCases = [
        '域名：http://www.' . $remoteHost,
        '域名：https://www.' . $remoteHost,
        '域名：http://' . $remoteHost,
        '域名：https://' . $remoteHost,
        'href="http://www.' . $remoteHost,
        'href="https://www.' . $remoteHost,
    ];
    
    foreach ($specialCases as $case) {
        $replacement = str_replace([
            'http://www.' . $remoteHost,
            'https://www.' . $remoteHost,
            'http://' . $remoteHost,
            'https://' . $remoteHost,
        ], $localDomain, $case);
        
        $content = str_replace($case, $replacement, $content);
    }
    
    // 第三步：直接字符串替换（作为最后手段）
    $content = str_ireplace(
        [
            'www.shuyous.com',
            'shuyous.com',
        ],
        $localHost,
        $content
    );
    
    return $content;
}
// 组合使用
function rewriteAllContentUrls($content, $remoteDomain, $localDomain) {
    $content = rewriteAllUrls($content, $remoteDomain, $localDomain);
    $content = rewriteTextUrls($content, $remoteDomain, $localDomain);
    $content = rewriteUrlsInComments($content, $remoteDomain, $localDomain);
    // 如果还有问题，使用更激进的方法
    if (strpos($content, 'shuyous.com') !== false || strpos($content, 'www.shuyous.com') !== false) {
        $content = rewriteAllUrlsAggressive($content, $remoteDomain, $localDomain);
        $content = rewriteUrlsTwoStep($content, $remoteDomain, $localDomain);
    }
    return $content;
}
//方案三：使用DOM解析器（更精确但稍慢）
function rewriteUrlsWithDOM($html, $remoteDomain, $localDomain) {
    $remoteHost = parse_url($remoteDomain, PHP_URL_HOST);
    
    // 使用DOMDocument处理HTML结构
    $dom = new DOMDocument();
    @$dom->loadHTML(mb_convert_encoding($html, 'HTML-ENTITIES', 'UTF-8'), LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD);
    
    // 处理所有链接
    $tags = array('a', 'link', 'img', 'script', 'iframe', 'form', 'meta');
    foreach ($tags as $tag) {
        $elements = $dom->getElementsByTagName($tag);
        foreach ($elements as $element) {
            $attributes = array('href', 'src', 'action', 'content', 'data-src');
            foreach ($attributes as $attr) {
                if ($element->hasAttribute($attr)) {
                    $url = $element->getAttribute($attr);
                    if (strpos($url, $remoteHost) !== false) {
                        $newUrl = str_replace($remoteDomain, $localDomain, $url);
                        $element->setAttribute($attr, $newUrl);
                    }
                }
            }
        }
    }
    
    // 处理文本节点中的URL
    $xpath = new DOMXPath($dom);
    $textNodes = $xpath->query('//text()');
    
    foreach ($textNodes as $textNode) {
        $text = $textNode->nodeValue;
        if (strpos($text, $remoteHost) !== false) {
            $newText = preg_replace(
                '/(https?:\/\/' . preg_quote($remoteHost, '/') . '\/[^\s<>"\']+)/i',
                $localDomain . parse_url('$1', PHP_URL_PATH) . (parse_url('$1', PHP_URL_QUERY) ? '?' . parse_url('$1', PHP_URL_QUERY) : ''),
                $text
            );
            $textNode->nodeValue = $newText;
        }
    }
    
    return $dom->saveHTML();
}

// CSS URL重写函数
function rewriteUrlsInCss($cssContent, $remoteDomain, $localDomain) {
    $remoteHost = parse_url($remoteDomain, PHP_URL_HOST);
    $localHost = parse_url($localDomain, PHP_URL_HOST) ?: $_SERVER['HTTP_HOST'];
    
    // 正确处理CSS中的各种url()格式
    $patterns = [
        // 1. 绝对URL（带协议）
        '/url\s*\(\s*(["\']?)(https?:)?\/\/' . preg_quote($remoteHost, '/') . '(\/[^"\')]*)(["\']?)\s*\)/i',
        
        // 2. 协议相对URL
        '/url\s*\(\s*(["\']?)\/\/' . preg_quote($remoteHost, '/') . '(\/[^"\')]*)(["\']?)\s*\)/i',
        
        // 3. @import 规则
        '/@import\s+(["\'])(https?:)?\/\/' . preg_quote($remoteHost, '/') . '(\/[^"\']*)\1/i',
        
        // 4. @import 协议相对
        '/@import\s+(["\'])\/\/' . preg_quote($remoteHost, '/') . '(\/[^"\']*)\1/i',
    ];
    
    $replacements = [
        // 1. 绝对URL
        'url($1' . $localDomain . '$3$4)',
        
        // 2. 协议相对
        'url($1' . $localDomain . '$2$3)',
        
        // 3. @import 绝对
        '@import $1' . $localDomain . '$3$1',
        
        // 4. @import 协议相对
        '@import $1' . $localDomain . '$2$1',
    ];
    
    $cssContent = preg_replace($patterns, $replacements, $cssContent);
    
    return $cssContent;
}

// JS URL重写函数
function rewriteUrlsInJs($jsContent, $remoteDomain, $localDomain) {
    $remoteHost = parse_url($remoteDomain, PHP_URL_HOST);
    $localHost = parse_url($localDomain, PHP_URL_HOST) ?: $_SERVER['HTTP_HOST'];
    
    // 处理JS中的字符串URL（简单版本，复杂的可能需要解析器）
    $patterns = array(
        // 字符串中的绝对URL
        '/(["\'])(https?:)?\/\/' . preg_quote($remoteHost, '/') . '(\/[^"\']*)\1/',
        // fetch/ajax请求中的URL
        '/(fetch|axios\.get|axios\.post|\.ajax|\.get|\.post|\.load)\s*\(\s*["\'](https?:)?\/\/' . preg_quote($remoteHost, '/') . '(\/[^"\']*)["\']/i',
    );
    
    $replacements = array(
        '$1' . $localDomain . '$3$1',
        '$1("' . $localDomain . '$3"',
    );
    
    return preg_replace($patterns, $replacements, $jsContent);
}

//或者使用统一的URL重写函数：
// 统一的URL重写函数
function rewriteResourceUrls($content, $remoteDomain, $localDomain, $contentType) {
    $remoteHost = parse_url($remoteDomain, PHP_URL_HOST);
    $localHost = parse_url($localDomain, PHP_URL_HOST) ?: $_SERVER['HTTP_HOST'];
    
    // 根据内容类型使用不同的替换策略
    switch($contentType) {
        case 'css':
            // CSS特定替换
            $patterns = array(
                '/url\s*\(\s*(["\']?)(https?:)?\/\/' . preg_quote($remoteHost, '/') . '(\/[^"\')]*)(["\']?)\s*\)/i',
                '/@import\s+(["\'])(https?:)?\/\/' . preg_quote($remoteHost, '/') . '(\/[^"\']*)\1/i',
            );
            $replacements = array(
                'url($1' . $localDomain . '$3$4)',
                '@import $1' . $localDomain . '$3$1',
            );
            break;
            
        case 'js':
            // JS特定替换（保守一点，避免替换代码逻辑）
            $patterns = array(
                '/(["\'])(https?:)?\/\/' . preg_quote($remoteHost, '/') . '(\/static\/[^"\']*)\1/',
                '/(["\'])(https?:)?\/\/' . preg_quote($remoteHost, '/') . '(\/assets\/[^"\']*)\1/',
                '/(["\'])(https?:)?\/\/' . preg_quote($remoteHost, '/') . '(\/images\/[^"\']*)\1/',
                '/(["\'])(https?:)?\/\/' . preg_quote($remoteHost, '/') . '(\/css\/[^"\']*)\1/',
                '/(["\'])(https?:)?\/\/' . preg_quote($remoteHost, '/') . '(\/js\/[^"\']*)\1/',
            );
            $replacements = array(
                '$1' . $localDomain . '$3$1',
                '$1' . $localDomain . '$3$1',
                '$1' . $localDomain . '$3$1',
                '$1' . $localDomain . '$3$1',
                '$1' . $localDomain . '$3$1',
            );
            break;
            
        default:
            // 通用替换（用于HTML等）
            $patterns = array(
                '/(href|src|action|data-src|data-href)\s*=\s*["\'](https?:)?\/\/' . preg_quote($remoteHost, '/') . '(\/[^"\']*)["\']/i',
                '/(url\s*\(\s*["\'])(https?:)?\/\/' . preg_quote($remoteHost, '/') . '(\/[^"\']*)["\']\s*\)/i',
            );
            $replacements = array(
                '$1="' . $localDomain . '$3"',
                '$1' . $localDomain . '$3"$4)',
            );
    }
    
    return preg_replace($patterns, $replacements, $content);
}

// 在静态资源中使用：
/*
if ($ext === 'css') {
    $body = rewriteResourceUrls($body, $host, 'http://' . $_SERVER['HTTP_HOST'], 'css');
} elseif ($ext === 'js') {
    $body = rewriteResourceUrls($body, $host, 'http://' . $_SERVER['HTTP_HOST'], 'js');
}
*/
// 只对文本文件进行重写
/*
$textExtensions = ['css', 'js', 'html', 'htm', 'xml', 'json', 'txt'];
if (in_array($ext, $textExtensions)) {
    $body = rewriteResourceUrls($body, $host, 'http://' . $_SERVER['HTTP_HOST'], $ext);
}
*/

//方案三：智能缓存（推荐）
class StaticCache {
    private $cacheDir;
    private $cacheTime;
    private $cachePrefix = 'static_';
    
    public function __construct($cacheTime = 3600) {
        $this->cacheDir = dirname(__FILE__) . '/static_cache';
        $this->cacheTime = $cacheTime;
        
        if (!is_dir($this->cacheDir)) {
            @mkdir($this->cacheDir, 0755, true);
        }
        
        // 可选：自动清理过期缓存（低概率触发，避免频繁IO）
        $this->autoCleanExpired();
    }
    
    public function get($key) {
        $file = $this->getCacheFilePath($key);
        if (file_exists($file) && (time() - filemtime($file)) < $this->cacheTime) {
            return file_get_contents($file);
        }
        return false;
    }
    
    public function set($key, $content) {
        $file = $this->getCacheFilePath($key);
        return file_put_contents($file, $content);
    }
    
    public function getCacheHeaders($ext) {
        $headers = [];
        
        // 根据文件类型设置缓存时间
        switch($ext) {
            case 'css':
            case 'js':
                $maxAge = 604800; // 7天
                break;
            case 'png':
            case 'jpg':
            case 'jpeg':
            case 'gif':
            case 'ico':
            case 'svg':
                $maxAge = 2592000; // 30天
                break;
            case 'woff':
            case 'woff2':
            case 'ttf':
            case 'eot':
                $maxAge = 31536000; // 1年
                break;
            default:
                $maxAge = 86400; // 1天
        }
        
        $headers['Cache-Control'] = 'public, max-age=' . $maxAge;
        $headers['Expires'] = gmdate('D, d M Y H:i:s', time() + $maxAge) . ' GMT';
        
        return $headers;
    }
    
    /**
     * 清除单个缓存项
     * @param string $key 缓存键
     * @return bool 是否成功
     */
    public function delete($key) {
        $file = $this->getCacheFilePath($key);
        $metaFile = $this->getMetaFilePath($key);
        
        $deleted = false;
        if (file_exists($file)) {
            $deleted = @unlink($file);
        }
        if (file_exists($metaFile)) {
            @unlink($metaFile);
        }
        
        return $deleted;
    }
    
    /**
     * 清除所有静态缓存
     * @param bool $includeMeta 是否同时删除元数据文件
     * @return int 删除的文件数量
     */
    public function cleanAll($includeMeta = true) {
        $count = 0;
        
        if (!is_dir($this->cacheDir)) {
            return $count;
        }
        
        $files = scandir($this->cacheDir);
        foreach ($files as $file) {
            if ($file === '.' || $file === '..') {
                continue;
            }
            
            $filePath = $this->cacheDir . DIRECTORY_SEPARATOR . $file;
            
            // 根据参数决定删除哪些文件
            if ($includeMeta) {
                // 删除所有文件
                if (@unlink($filePath)) {
                    $count++;
                }
            } else {
                // 只删除缓存文件，保留元数据文件
                if (strpos($file, $this->cachePrefix) === 0 && 
                    !strpos($file, '.meta')) {
                    if (@unlink($filePath)) {
                        $count++;
                    }
                }
            }
        }
        
        return $count;
    }
    
    /**
     * 清除过期缓存
     * @return int 删除的过期文件数量
     */
    public function cleanExpired() {
        $count = 0;
        
        if (!is_dir($this->cacheDir)) {
            return $count;
        }
        
        $files = scandir($this->cacheDir);
        $now = time();
        
        foreach ($files as $file) {
            if ($file === '.' || $file === '..') {
                continue;
            }
            
            // 只处理缓存文件，不处理元数据文件
            if (strpos($file, $this->cachePrefix) === 0 && 
                !strpos($file, '.meta')) {
                
                $filePath = $this->cacheDir . DIRECTORY_SEPARATOR . $file;
                if (filemtime($filePath) < $now - $this->cacheTime) {
                    // 删除缓存文件
                    if (@unlink($filePath)) {
                        $count++;
                    }
                    
                    // 同时删除对应的元数据文件
                    $metaFile = $this->getMetaFilePathByCacheFile($file);
                    if (file_exists($metaFile)) {
                        @unlink($metaFile);
                    }
                }
            }
        }
        
        return $count;
    }
    
    /**
     * 获取缓存统计信息
     * @return array 缓存统计信息
     */
    public function getStats() {
        $stats = [
            'total_files' => 0,
            'total_size' => 0,
            'expired_files' => 0,
            'cache_dir' => $this->cacheDir,
            'cache_time' => $this->cacheTime,
        ];
        
        if (!is_dir($this->cacheDir)) {
            return $stats;
        }
        
        $files = scandir($this->cacheDir);
        $now = time();
        
        foreach ($files as $file) {
            if ($file === '.' || $file === '..') {
                continue;
            }
            
            $filePath = $this->cacheDir . DIRECTORY_SEPARATOR . $file;
            
            // 只统计缓存文件
            if (strpos($file, $this->cachePrefix) === 0 && 
                !strpos($file, '.meta')) {
                
                $stats['total_files']++;
                $stats['total_size'] += filesize($filePath);
                
                if (filemtime($filePath) < $now - $this->cacheTime) {
                    $stats['expired_files']++;
                }
            }
        }
        
        // 格式化文件大小
        $stats['total_size_formatted'] = $this->formatBytes($stats['total_size']);
        
        return $stats;
    }
    
    /**
     * 获取缓存目录路径
     * @return string 缓存目录路径
     */
    public function getCacheDir() {
        return $this->cacheDir;
    }
    
    /**
     * 设置缓存时间
     * @param int $seconds 缓存时间（秒）
     */
    public function setCacheTime($seconds) {
        $this->cacheTime = $seconds;
    }
    
    // ============ 私有方法 ============
    
    private function getCacheFilePath($key) {
        return $this->cacheDir . DIRECTORY_SEPARATOR . $this->cachePrefix . md5($key);
    }
    
    private function getMetaFilePath($key) {
        return $this->getCacheFilePath($key) . '.meta';
    }
    
    private function getMetaFilePathByCacheFile($cacheFilename) {
        return $this->cacheDir . DIRECTORY_SEPARATOR . $cacheFilename . '.meta';
    }
    
    /**
     * 自动清理过期缓存（低概率触发）
     */
    private function autoCleanExpired() {
        // 1%的概率触发自动清理，避免频繁IO
        if (mt_rand(1, 100) === 1) {
            $this->cleanExpired();
        }
    }
    
    /**
     * 格式化字节大小
     * @param int $bytes 字节数
     * @param int $precision 精度
     * @return string 格式化后的字符串
     */
    private function formatBytes($bytes, $precision = 2) {
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        $bytes = max($bytes, 0);
        $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
        $pow = min($pow, count($units) - 1);
        $bytes /= pow(1024, $pow);
        
        return round($bytes, $precision) . ' ' . $units[$pow];
    }
}

// 使用
/*
$staticCache = new StaticCache(3600); // 服务器缓存1小时
$cacheKey = md5($remote);

if ($cached = $staticCache->get($cacheKey)) {
    $headers = $staticCache->getCacheHeaders($ext);
    foreach ($headers as $name => $value) {
        header($name . ': ' . $value);
    }
    echo $cached;
    exit;
}
// 1. 初始化
$staticCache = new StaticCache(3600); // 1小时缓存

// 2. 清除所有缓存
$deletedCount = $staticCache->cleanAll();
echo "删除了 {$deletedCount} 个缓存文件";

// 3. 清除过期缓存
$expiredCount = $staticCache->cleanExpired();
echo "删除了 {$expiredCount} 个过期缓存文件";

// 4. 清除单个缓存
$staticCache->delete('http://example.com/style.css');

// 5. 获取统计信息
$stats = $staticCache->getStats();
echo "缓存目录: " . $stats['cache_dir'] . "\n";
echo "文件数量: " . $stats['total_files'] . "\n";
echo "缓存大小: " . $stats['total_size_formatted'] . "\n";
echo "过期文件: " . $stats['expired_files'] . "\n";
*/
// ... 从远程获取、处理、重写URL ...

// 保存到缓存
//$staticCache->set($cacheKey, $body);