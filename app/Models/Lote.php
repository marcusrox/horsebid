<?php

namespace App\Models;

use Spatie\Activitylog\Traits\LogsActivity;

class Lote extends BaseModel
{

    protected $table = 'lotes';

    // public function rules()
    // {
    //     return [
    //         'nome' => 'required|unique:lotes,nome,' . $this->id,
    //         'leilao_id' => 'required',
    //         'vendedor_id' => 'required',
    //     ];
    // }

    protected $guarded = []; // Não precisa colocar os campos no fillable

    public function leilao()
    {
        return $this->belongsTo('App\Models\Leilao');
    }

    public function vendedor()
    {
        return $this->belongsTo('App\Models\Vendedor');
    }

    public function arremates()
    {
        return $this->hasMany('App\Models\Arremate');
    }
}
