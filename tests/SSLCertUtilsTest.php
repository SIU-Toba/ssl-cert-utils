<?php

use PHPUnit\Framework\TestCase;

/**
 * Created by IntelliJ IDEA.
 * User: andres
 * Date: 24/09/15
 * Time: 18:08
 */
class SSLCertUtilsTest extends TestCase
{
    public function testGetCN()
    {
        $utils = new \SIUToba\SSLCertUtils\SSLCertUtils();
        $utils->loadCertFromFile(__DIR__."/fixtures/cliente.cert.pem");
        $this->assertEquals($utils->getCN(), "cliente2");
    }

    public function testGetFingerprint()
    {
        $utils = new \SIUToba\SSLCertUtils\SSLCertUtils();
        $utils->loadCertFromFile(__DIR__."/fixtures/cliente.cert.pem");
        $this->assertEquals($utils->getFingerprint(), "81c2df2298d9b66b7cf96408b75a39cb36071062");
    }
}
