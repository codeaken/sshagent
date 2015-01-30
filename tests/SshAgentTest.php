<?php
namespace Codeaken\SshAgent\Tests;

use Codeaken\SshAgent\SshAgent;
use Codeaken\SshKey\SshPrivateKey;

class SshAgentTest extends \PHPUnit_Framework_TestCase
{
    protected $keysDir;

    protected function setUp()
    {
        $this->keysDir = dirname(__FILE__) . '/keys';
    }

    public function testStart()
    {
        $agent = new SshAgent();

        $this->assertTrue($agent->start());

        // Do not allow starting a new agent before the already running one is
        // stopped
        $this->assertFalse($agent->start());
    }

    public function testStop()
    {
        $agent = new SshAgent();

        // Return true even if there wasnt a running agent to start with
        $this->assertTrue($agent->stop());

        $agent->start();
        $this->assertTrue($agent->stop());
    }

    public function testIsRunning()
    {
        $agent = new SshAgent();

        $this->assertFalse($agent->isRunning());

        $agent->start();
        $this->assertTrue($agent->isRunning());
    }

    public function testGetPid()
    {
        $agent = new SshAgent();

        $this->assertEquals(0, $agent->getPid());

        $agent->start();
        $this->assertGreaterThan(0, $agent->getPid());
    }

    public function testGetSocket()
    {
        $agent = new SshAgent();

        $this->assertEmpty($agent->getSocket());

        $agent->start();

        // Very simple test to see if we have something that looks like a path
        // by checking if we have one or more directory separators (/)
        $this->assertRegExp('/\/+/', $agent->getSocket());
    }

    public function testAddKey()
    {
        $key = SshPrivateKey::fromFile("{$this->keysDir}/id_nopass_rsa");

        $agent = new SshAgent();

        // Agent is not running so not possible to add a key to it
        $this->assertFalse($agent->addKey($key));

        $agent->start();
        $this->assertTrue($agent->addKey($key));
    }
}
