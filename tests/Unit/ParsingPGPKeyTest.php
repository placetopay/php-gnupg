<?php

namespace Tests\Unit;

class ParsingPGPKeyTest extends \Tests\BaseTestCase
{
    /**
     * @test
     */
    public function it_parses_all_owner_information()
    {
        $inputs = [
            ['Diego Arturo Calle Mora (ID) <diego.calle@placetopay.com>', 'Diego Arturo Calle Mora', 'ID', 'diego.calle@placetopay.com'],
            ['Diego A. Calle M. (DACM) <dnetix@gmail.com>', 'Diego A. Calle M.', 'DACM', 'dnetix@gmail.com'],
            ['PlacetoPay Services (File Transfer) <operaciones@placetopay.com>', 'PlacetoPay Services', 'File Transfer', 'operaciones@placetopay.com'],
            ['Marco Espinosa <marespito@gmail.com>', 'Marco Espinosa', '', 'marespito@gmail.com'],
            ['PLACE TO PAY - File transfer (www.placetopay.com) <operaciones@placetopay.com>', 'PLACE TO PAY - File transfer', 'www.placetopay.com', 'operaciones@placetopay.com'],
            ['llavero_medellin()<julian.naranjo@medellin.gov.co>', 'llavero_medellin', '', 'julian.naranjo@medellin.gov.co'],
            ['GitHub (web-flow commit signing) <noreply@github.com>', 'GitHub', 'web-flow commit signing', 'noreply@github.com'],
            ['José Niño (web-flow commit signing) <noreply@github.com>', 'José Niño', 'web-flow commit signing', 'noreply@github.com'],
        ];

        foreach ($inputs as $input) {
            $result = \PlacetoPay\GnuPG\Entities\PGPKey::parseOwner($input[0]);

            $this->assertEquals($input[1], $result['name'], 'It matches the name');
            $this->assertEquals($input[2], $result['comment'], 'It matches the comment');
            $this->assertEquals($input[3], $result['email'], 'It matches the email');
        }
    }
}
