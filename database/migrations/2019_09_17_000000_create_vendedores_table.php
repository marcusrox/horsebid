<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class CreateVendedoresTable extends Migration
{

    public function up()
    {
        Schema::create('vendedores', function (Blueprint $table) {
            $table->id();

            $table->string('tipo_pessoa')->length(1);
            $table->string('nome');
            $table->string('cpf_cnpj');
            $table->string('razao_social')->nullable();
            $table->string('telefone')->nullable();
            $table->string('celular');
            $table->string('endereco');
            $table->string('numero');
            $table->string('complemento')->nullable();
            $table->string('bairro');
            $table->string('cep');
            $table->string('cidade');
            $table->string('uf')->length(2);

            $table->foreignId('user_id')->constrained();
            $table->timestamps();
            $table->unsignedBigInteger('created_by')->nullable();
            $table->unsignedBigInteger('updated_by')->nullable();
        });

        // Schema::table('vendedores', function (Blueprint $table) {
        //     $table->foreign('user_id')->references('id')->on('users')
        //         ->onDelete('restrict')
        //         ->onUpdate('restrict');
        // });
    }

    public function down()
    {
        Schema::drop('vendedores');
    }
}
