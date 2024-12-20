<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use App\Models\Vendedor;

class VendedorTableSeeder extends Seeder {

	public function run()
	{
		//DB::table('vendedores')->delete();

		// SeedVendedores
		Vendedor::create(array(
				'cpf_cnpj' => '881.425.700-09',
                'nome' => 'Lucas Vendedor da Silva',
                'razao_social' => 'Lucas Vendedor da Silva',
                'tipo_pessoa' => 'F',
				'telefone' => '(71) 98888-5566',
				'user_id' => '2',
				'created_by' => 1,
				'updated_by' => 1,
			));
	}
}