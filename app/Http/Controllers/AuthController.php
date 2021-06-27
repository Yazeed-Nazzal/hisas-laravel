<?php
namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
/**
* Create a new AuthController instance.
*
* @return void
*/
public function __construct()
{
$this->middleware('auth:api', ['except' => ['login','register']]);
}

/**
* Get a JWT via given credentials.
*
* @return \Illuminate\Http\JsonResponse
*/
public function login()
{
    $credentials = request(['email', 'password']);
    if(filter_var(request('email'), FILTER_VALIDATE_EMAIL)) {
        if (! $token = auth()->attempt(['email'=>$credentials['email'],'password'=>$credentials['password']])) {
            return response()->json(['error' => 'Email or password is not correct'], 401);
        }
    }
    else{

        if (! $token = auth()->attempt(['phone'=>$credentials['email'],'password'=>$credentials['password']])) {
            return response()->json(['error' => 'Email or password is not correct'], 401);
        }
    }





return $this->respondWithToken($token);
}
public function register(Request  $request)
    {


        $validator = Validator::make($request->all(), [
            'fullName'   => 'required',
            'password' =>'required|min:6',
            'city' => 'required',
            'gender'  => 'required',
            'grade'   => 'required',
            'email'   => 'required',
            'phone'   => 'required',
        ]);

        if ($validator->stopOnFirstFailure()->fails()) {

            return response()->json($validator->errors());

        }
        else{
            User::create([
                'name' => $request->fullName,
                'email'=> $request->email,
                "password" => Hash::make($request->password),
                'city'    => $request->city,
                'gender'  => $request->gender,
                'grade'   => $request->grade,
                'phone'   => $request->phone,
            ]);
            return response()->json([
                "type" => "success"
            ]);
        }

    }

/**
* Get the authenticated User.
*
* @return \Illuminate\Http\JsonResponse
*/
public function me()
{
return response()->json(auth()->user());
}

/**
* Log the user out (Invalidate the token).
*
* @return \Illuminate\Http\JsonResponse
*/
public function logout()
{
auth()->logout();

return response()->json(['message' => 'Successfully logged out']);
}

/**
* Refresh a token.
*
* @return \Illuminate\Http\JsonResponse
*/
public function refresh()
{
return $this->respondWithToken(auth()->refresh());
}

/**
* Get the token array structure.
*
* @param  string $token
*
* @return \Illuminate\Http\JsonResponse
*/
protected function respondWithToken($token)
{
return response()->json([
'access_token' => $token,
'user'       => auth()->user()
]);
}
}
