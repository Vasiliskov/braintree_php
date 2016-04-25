<?php
namespace Braintree;

/**
 * Braintree HTTP Client
 * processes Http requests using curl
 *
 * @copyright  2015 Braintree, a division of PayPal, Inc.
 */
class Http
{
    protected $_config;
    private $_useClientCredentials = false;

    public function __construct($config)
    {
        $this->_config = $config;
    }

    public function delete($path)
    {
        $response = $this->_doRequest('DELETE', $path);
        if($response['status'] === 200) {
            return true;
        } else {
            Util::throwStatusCodeException($response['status']);
        }
    }

    public function get($path)
    {
        $response = $this->_doRequest('GET', $path);
        if ($response['status'] === 200) {
            return Xml::buildArrayFromXml($response['body']);
        } else {
            Util::throwStatusCodeException($response['status']);
        }
    }

    public function post($path, $params = null)
    {
        $response = $this->_doRequest('POST', $path, $this->_buildXml($params));
        $responseCode = $response['status'];
        if($responseCode === 200 || $responseCode === 201 || $responseCode === 422 || $responseCode == 400) {
            return Xml::buildArrayFromXml($response['body']);
        } else {
            Util::throwStatusCodeException($responseCode);
        }
    }

    public function put($path, $params = null)
    {
        $response = $this->_doRequest('PUT', $path, $this->_buildXml($params));
        $responseCode = $response['status'];
        if($responseCode === 200 || $responseCode === 201 || $responseCode === 422 || $responseCode == 400) {
            return Xml::buildArrayFromXml($response['body']);
        } else {
            Util::throwStatusCodeException($responseCode);
        }
    }

    private function _buildXml($params)
    {
        return empty($params) ? null : Xml::buildXmlFromArray($params);
    }

    private function _getHeaders()
    {
        return [
            'Accept: application/xml',
            'Content-Type: application/xml',
        ];
    }

    private function _getAuthorization()
    {
        if ($this->_useClientCredentials) {
            return [
                'user' => $this->_config->getClientId(),
                'password' => $this->_config->getClientSecret(),
            ];
        } else if ($this->_config->isAccessToken()) {
            return [
                'token' => $this->_config->getAccessToken(),
            ];
        } else {
            return [
                'user' => $this->_config->getPublicKey(),
                'password' => $this->_config->getPrivateKey(),
            ];
        }
    }

    public function useClientCredentials()
    {
        $this->_useClientCredentials = true;
    }

    private function _doRequest($httpVerb, $path, $requestBody = null)
    {
        if (!$this->_config->getUseMockResponse()) {
            $result = $this->_doUrlRequest($httpVerb, $this->_config->baseUrl() . $path, $requestBody);
            if ($this->_config->getSaveMockResponse()) {
                $this->saveMock($httpVerb, $this->_config->baseUrl() . $path, $requestBody, $result);
            }
        } else {
            $result = $this->_doMockRequest($httpVerb, $this->_config->baseUrl() . $path, $requestBody);
        }
        return $result;
    }

    public function _doUrlRequest($httpVerb, $url, $requestBody = null)
    {
        $curl = curl_init();
        curl_setopt($curl, CURLOPT_TIMEOUT, $this->_config->timeout());
        curl_setopt($curl, CURLOPT_CUSTOMREQUEST, $httpVerb);
        curl_setopt($curl, CURLOPT_URL, $url);
        curl_setopt($curl, CURLOPT_ENCODING, 'gzip');

        $headers = $this->_getHeaders($curl);
        $headers[] = 'User-Agent: Braintree PHP Library ' . Version::get();
        $headers[] = 'X-ApiVersion: ' . Configuration::API_VERSION;

        $authorization = $this->_getAuthorization();
        if (isset($authorization['user'])) {
            curl_setopt($curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
            curl_setopt($curl, CURLOPT_USERPWD, $authorization['user'] . ':' . $authorization['password']);
        } else if (isset($authorization['token'])) {
            $headers[] = 'Authorization: Bearer ' . $authorization['token'];
        }
        curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);

        // curl_setopt($curl, CURLOPT_VERBOSE, true);
        if ($this->_config->sslOn()) {
            curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, true);
            curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, 2);
            curl_setopt($curl, CURLOPT_CAINFO, $this->getCaFile());
        }

        if(!empty($requestBody)) {
            curl_setopt($curl, CURLOPT_POSTFIELDS, $requestBody);
        }

        if($this->_config->isUsingProxy()) {
            $proxyHost = $this->_config->getProxyHost();
            $proxyPort = $this->_config->getProxyPort();
            $proxyType = $this->_config->getProxyType();
            curl_setopt($curl, CURLOPT_PROXY, $proxyHost . ':' . $proxyPort);
            if(!empty($proxyType)) {
                curl_setopt($curl, CURLOPT_PROXYTYPE, $proxyType);
            }
        }

        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        $response = curl_exec($curl);
        $httpStatus = curl_getinfo($curl, CURLINFO_HTTP_CODE);
        $error_code = curl_errno($curl);

        if ($error_code == 28 && $httpStatus == 0) {
            throw new Exception\Timeout();
        }

        curl_close($curl);
        if ($this->_config->sslOn()) {
            if ($httpStatus == 0) {
                throw new Exception\SSLCertificate();
            }
        }
        return ['status' => $httpStatus, 'body' => $response];
    }

    private function getCaFile()
    {
        static $memo;

        if ($memo === null) {
            $caFile = $this->_config->caFile();

            if (substr($caFile, 0, 7) !== 'phar://') {
                return $caFile;
            }

            $extractedCaFile = sys_get_temp_dir() . '/api_braintreegateway_com.ca.crt';

            if (!file_exists($extractedCaFile) || sha1_file($extractedCaFile) != sha1_file($caFile)) {
                if (!copy($caFile, $extractedCaFile)) {
                    throw new Exception\SSLCaFileNotFound();
                }
            }
            $memo = $extractedCaFile;
        }

        return $memo;
    }

    /**
     * Getting mock response.
     *
     * @param string   $httpVerb        HTTP request method
     * @param string   $requestUrl      Full API endpoint URL
     * @param mixed    $requestBody     Request body.
     *
     * @return array    Mock response.
     */
    private function _doMockRequest ($httpVerb, $requestUrl, $requestBody) {
        if (!is_string($requestBody)) {
            $requestBody = print_r($requestBody, true);
        }
        $filename = $this->_config->getMockResponsesDir() . md5($httpVerb) . md5($requestUrl) . md5($requestBody) . '.inc';
        if (file_exists($filename)) {
            $data = null;
            require $filename;
            return $data;
        } else {
            return ['status' => 404, 'body' => ''];
        }
    }

    /**
     * Saving mock response.
     *
     * @param string   $httpVerb        HTTP request method
     * @param string   $requestUrl      Full API endpoint URL
     * @param mixed    $requestBody     Request body.
     * @param mixed    $response        Response body
     */
    private function saveMock ($httpVerb, $requestUrl, $requestBody, $response) {
        if (!file_exists($this->_config->getMockResponsesDir())) {
            mkdir($this->_config->getMockResponsesDir(), 0777, true);
        }
        if (!is_string($requestBody)) {
            $requestBody = print_r($requestBody, true);
        }
        $response     = htmlspecialchars($response['body'], ENT_QUOTES);
        $data         = "<?\n\$data = array('status' => $response[status], \n'body' => '$response');";
        $filename     = $this->_config->getMockResponsesDir() . md5($httpVerb) . md5($requestUrl) . md5($requestBody) . '.inc';
        file_put_contents($filename, $data);
        if ($this->_config->getEnvironment() == 'sandbox') {
            $requestData = "<?\n\$reqdata = array('url' => '$requestUrl', \n'body' => '$requestBody');";
            $filename    = $this->_config->getMockResponsesDir() . md5($requestUrl) . md5($requestBody) . '_req.inc';
            file_put_contents($filename, $requestData);
        }
    }
}
class_alias('Braintree\Http', 'Braintree_Http');
