<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\Hash;
use Laravel\Sanctum\PersonalAccessToken;
use Symfony\Component\HttpFoundation\Response;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        return User::create([
            'name' => $request->input('name'),
            'email' => $request->input('email'),
            'password' => Hash::make($request->input('password'))
        ]);
    }

    public function login(Request $request)
    {
        if (!Auth::attempt($request->only('email', 'password'))) {
            return response([
                'message' => 'Invalid credentials!'
            ], Response::HTTP_UNAUTHORIZED);
        }

        $user = Auth::user();

        $accessToken = $user->createToken('access_token')->plainTextToken;
        $refreshToken = $user->createToken('refresh_token')->plainTextToken;

        $cookie = cookie('refreshToken', $refreshToken, 60 * 24 * 7); // 1 week

        return response([
            'token' => $accessToken
        ])->withCookie($cookie);
    }

    public function user()
    {
        return Auth::user();
    }

    public function refresh(Request $request)
    {
        $refreshToken = $request->cookie('refreshToken');

        $token = PersonalAccessToken::findToken($refreshToken);

        $user = $token->tokenable;

        $accessToken = $user->createToken('access_token')->plainTextToken;

        return response([
            'token' => $accessToken
        ]);
    }

    public function logout()
    {
        $cookie = Cookie::forget('refreshToken');

        return response([
            'message' => 'Success'
        ])->withCookie($cookie);
    }
}
