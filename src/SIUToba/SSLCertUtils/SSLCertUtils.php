<?php

namespace SIUToba\SSLCertUtils;

class SSLCertUtils
{
    protected $cert;
    public function __construct()
    {
        $this->cert = false;
    }

    public function loadCert($cert)
    {
        $this->cert = $cert;
    }

    public function loadCertFromFile($filename)
    {
        $res = file_get_contents($filename);
        if ($res === false) {
            throw new \Exception("El archivo '$filename' no pudo ser leído");
        }

        $this->cert = $res;
    }

    public function getCN()
    {
        $this->checkLoaded();
        $parsed = openssl_x509_parse($this->cert);
        return $parsed['subject']['CN'];
    }

    public function getBase64()
    {
        $this->checkLoaded();
        $output = null;

        $resource = openssl_x509_read($this->cert);
        if (false === $resource) {
            //error_log(var_export($this->cert, true));
            throw new \Exception("El certificado no es un certificado valido.");
        }

        $result = openssl_x509_export($resource, $output);
        if($result !== false) {
            $output = str_replace('-----BEGIN CERTIFICATE-----', '', $output);
            $output = str_replace('-----END CERTIFICATE-----', '', $output);
            return base64_decode($output);
        } else {
            throw new \Exception("El certificado no se pudo exportar a string.");
        }
    }

    public function getFingerprint(string $algo = 'sha1')
    {
        $this->checkLoaded();
        return hash($algo, $this->getBase64());
    }

    protected function checkLoaded()
    {
        if ($this->cert === false) {
            throw new \Exception("Antes de usar esta clase debe cargar un certificado con alguna de las funciones SSLCertUtils::loadCert*");
        }
    }
}
