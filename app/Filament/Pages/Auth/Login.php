<?php

namespace App\Filament\Pages\Auth;

use Filament\Facades\Filament;
use Filament\Pages\Auth\Login as BasePage;
use Filament\Models\Contracts\FilamentUser;
use Illuminate\Validation\ValidationException;
use Filament\Http\Responses\Auth\Contracts\LoginResponse;
use DanHarrin\LivewireRateLimiting\Exceptions\TooManyRequestsException;

class Login extends BasePage
{
    public function authenticate(): ?LoginResponse
    {
        try {
            $this->rateLimit(5);
        } catch (TooManyRequestsException $exception) {
            $this->getRateLimitedNotification($exception)?->send();

            return null;
        }

        $data = $this->form->getState();

        if (! Filament::auth()->attempt($this->getCredentialsFromFormData($data), $data['remember'] ?? false)) {
            $this->throwFailureValidationException();
        }

        $user = Filament::auth()->user();

        if (($user instanceof FilamentUser) && (! $user->canAccessPanel(Filament::getCurrentPanel()))) {
            Filament::auth()->logout();

            $this->throwFailureValidationException();
        } elseif (!$user->active) {
            Filament::auth()->logout();

            throw ValidationException::withMessages([
                'data.email' => 'A sua conta não está ativa',
            ]);
        } elseif ($user->roles->count() === 0) {
            Filament::auth()->logout();

            throw ValidationException::withMessages([
                'data.email' => 'A sua conta não está vinculada com nenhum grupo de usuários',
            ]);
        }


        session()->regenerate();

        return app(LoginResponse::class);
    }
}
