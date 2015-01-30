<?php
namespace Codeaken\SshAgent;

use Symfony\Component\Process\Process;
use Codeaken\SshKey\SshKey;
use Codeaken\SshKey\SshPrivateKey;

class SshAgent
{
    protected $pid = 0;
    protected $socket = '';

    public function __destruct()
    {
        $this->stop();
    }

    public function start()
    {
        if ($this->isRunning()) {
            // Do not allow starting a new agent if there is one already running.
            return false;
        }

        $agent = new Process('ssh-agent -s');
        $agent->run();

        if ( ! $agent->isSuccessful()) {
            return false;
        }

        // Parse the output for socket and pid
        preg_match_all(
            '/\s*(.*?)=(.*?);/',
            $agent->getOutput(),
            $matches,
            PREG_SET_ORDER
        );

        foreach ($matches as $group) {
            switch ($group[1]) {
                 case 'SSH_AUTH_SOCK':
                     $this->socket = $group[2];
                     break;

                case 'SSH_AGENT_PID':
                    $this->pid = (int)$group[2];
                    break;
             }
        }

        return true;
    }

    public function stop()
    {
        if ($this->isRunning()) {
            $kill = new Process("kill -s TERM {$this->pid}");
            $kill->run();

            // Reset state
            $this->pid = 0;
            $this->socket = '';
        }
    }

    public function addKey(SshPrivateKey $key)
    {
        if ( ! $this->isRunning()) {
            // No point in trying to add a key to an agent that is not running
            // so abort early
            return false;
        }

        // Save the key to a temporary file
        $tmpKey = tempnam(sys_get_temp_dir(), 'codeaken_sshagent_');
        file_put_contents($tmpKey, $key->getKeyData(SshKey::FORMAT_PKCS8));

        $sshAdd = new Process(
            "ssh-add {$tmpKey}",
            null,
            [
                'SSH_AUTH_SOCK' => $this->getSocket()
            ],
            $key->getPassword() . "\n"
        );
        $sshAdd->setPty(true);
        $sshAdd->run();

        if ( ! $sshAdd->isSuccessful()) {
            unlink($tmpKey);
            return false;
        }

        unlink($tmpKey);
        return true;
    }

    public function getPid()
    {
        return $this->pid;
    }

    public function getSocket()
    {
        return $this->socket;
    }

    public function isRunning()
    {
        if (0 == $this->pid && empty($this->socket)) {
            return false;
        }

        return true;
    }
}
