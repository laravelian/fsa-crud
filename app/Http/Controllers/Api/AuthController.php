<?php

namespace App\Http\Controllers\Api;

use Illuminate\Http\Request;
use App\Http\Requests\LoginRequest;
use App\Http\Controllers\Controller;
use App\Http\Requests\SignupRequest;
use App\Models\User;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{
    public function signup(SignupRequest $request)
    {
        $data = $request->validated();
        $user = User::create([
            'name' => $data['name'],
            'email' => $data['email'],
            'password' => bcrypt($data['password']),
        ]);

        $token = $user->createToken('main')->plainTextToken;

        return response(compact('token', 'user'));
    }
    public function login(LoginRequest $request)
    {
        $credenciales = $request->validated();
        if (!Auth::attempt($credenciales)) {
            return response([
                'message' => 'correo y/o contraseña son invalidos'
            ], 422);
        }

        $user = Auth::user();
        $token = $user->createToken('main')->plainTextToken;
        return response(compact('token', 'user'));
    }
    public function logout(Request $request)
    {
        $user = $request->user();
        $user->currentAccessToken()->delete();
        return response('', 204);
    }
}
