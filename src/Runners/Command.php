<?php

namespace PlacetoPay\GnuPG\Runners;

class Command
{
    protected $command;

    public function __construct(string $command)
    {
        $this->command = $command;
    }

    public static function create(string $executable, array $arguments = []): self
    {
        $command = escapeshellcmd($executable);

        foreach ($arguments as $key => $value) {
            if (!isset($value)) {
                $command .= ' ' . $key;
            } else {
                $command .= ' ' . $key . ' ' . escapeshellarg($value);
            }
        }

        return new static($command);
    }

    public function run(string $input = ''): CommandResult
    {
        // define the redirection pipes
        $descriptorSpec = [
            0 => ['pipe', 'r'],  // stdin is a pipe that the child will read from
            1 => ['pipe', 'w'],  // stdout is a pipe that the child will write to
            2 => ['pipe', 'w'],   // stderr is a pipe that the child will write to
        ];
        $pipes = null;

        // calls the process
        $process = proc_open($this->command, $descriptorSpec, $pipes);
        if (is_resource($process)) {
            // writes the input
            if (!empty($input)) {
                fwrite($pipes[0], $input);
            }
            fclose($pipes[0]);

            // reads the output
            $output = '';
            while (!feof($pipes[1])) {
                $data = fread($pipes[1], 1024);
                if (strlen($data) == 0) {
                    break;
                }
                $output .= $data;
            }
            fclose($pipes[1]);

            // reads the error message
            $error = '';
            while (!feof($pipes[2])) {
                $data = fread($pipes[2], 1024);
                if (strlen($data) == 0) {
                    break;
                }
                $error .= $data;
            }
            fclose($pipes[2]);

            // close the process
            $status = proc_close($process);

            // returns the contents
            return new CommandResult($status, $output, $error, $this);
        } else {
            // TODO: Throw exception
//            $this->error = 'Unable to fork the command';
//            return false;
        }
    }

    public function command(): string
    {
        return $this->command;
    }
}
