using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using API.Dtos;
using API.Helpers;
using Dominio.Entities;
using Dominio.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;


namespace API.Services;
public class UserService : IUserService{
        private readonly JWT _jwt;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IPasswordHasher<Usuario> _passwordHasher;
        public UserService(IUnitOfWork unitOfWork, IOptions<JWT> jwt, IPasswordHasher<Usuario> passwordHasher)
        {
            _jwt = jwt.Value;
            _unitOfWork = unitOfWork;
            _passwordHasher = passwordHasher;
        }
        public async Task<string> RegisterAsync(RegisterDto registerDto)
        {
            var usuario = new Usuario
            {
                Email = registerDto.Email,
                Username = registerDto.Username,

            };

            usuario.Password = _passwordHasher.HashPassword(usuario, registerDto.Password!);

            var usuarioExiste = _unitOfWork.Usuarios
                                                .Find(u => u.Username!.ToLower() == registerDto.Username!.ToLower())
                                                .FirstOrDefault();

            if (usuarioExiste == null)
            {
                /* var rolPredeterminado = _unitOfWork.Rols
                                                     .Find(u => u.Name_Rol == Autorizacion.Rol_PorDefecto.ToString())
                                                     .First();*/
                try
                {
                    //usuario.Rols.Add(rolPredeterminado);
                    _unitOfWork.Usuarios.Add(usuario);
                    await _unitOfWork.SaveAsync();

                    return $"El Usuario {registerDto.Username} ha sido registrado exitosamente";
                }

                catch (Exception ex)
                {
                    var message = ex.Message;
                    return $"Error: {message}";
                }
            }
            else
            {

                return $"El usuario con {registerDto.Username} ya se encuentra resgistrado.";
            }

        }

        public async Task<string> AddRoleAsync(AddRoleDto model)
        {
            var usuario = await _unitOfWork.Usuarios
                                .GetByUsernameAsync(model.Username!);

            if (usuario == null)
            {
                return $"No existe algun usuario registrado con la cuenta olvido algun caracter?{model.Username}.";
            }

            var resultado = _passwordHasher.VerifyHashedPassword(usuario, usuario.Password!, model.Password!);

            if (resultado == PasswordVerificationResult.Success)
            {
                var rolExiste = _unitOfWork.Roles
                                                .Find(u => u.Nombre!.ToLower() == model.Rol!.ToLower())
                                                .FirstOrDefault();

                if (rolExiste != null)
                {
                    var usuarioTieneRol = usuario.Roles!
                                                    .Any(u => u.Id == rolExiste.Id);

                    if (usuarioTieneRol == false)
                    {
                        usuario.Roles!.Add(rolExiste);
                        _unitOfWork.Usuarios.Update(usuario);
                        await _unitOfWork.SaveAsync();
                    }

                    return $"Rol {model.Rol} agregado a la cuenta {model.Username} de forma exitosa.";
                }

                return $"Rol {model.Rol} no encontrado.";
            }

            return $"Credenciales incorrectas para el ususario {usuario.Username}.";
        }
        public async Task<DatosUsuarioDto> GetTokenAsync(LoginDto model)
        {
            DatosUsuarioDto datosUsuarioDto = new DatosUsuarioDto();
            var usuario = await _unitOfWork.Usuarios
                            .GetByUsernameAsync(model.Username!);

            if (usuario == null)
            {
                datosUsuarioDto.EstaAutenticado = false;
                datosUsuarioDto.Mensaje = $"No existe ningun usuario con el username {model.Username}.";
                return datosUsuarioDto;
            }

            var result = _passwordHasher.VerifyHashedPassword(usuario, usuario.Password!, model.Password!);
            if (result == PasswordVerificationResult.Success)
            {
                datosUsuarioDto.Mensaje = "OK";
                datosUsuarioDto.EstaAutenticado = true;
                if (usuario != null && usuario != null)
                {
                    JwtSecurityToken jwtSecurityToken = CreateJwtToken(usuario);
                    datosUsuarioDto.Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
                    datosUsuarioDto.UserName = usuario.Username;
                    datosUsuarioDto.Email = usuario.Email;
                    datosUsuarioDto.Roles = (usuario.Roles!
                                                        .Select(p => p.Nombre)
                                                        .ToList())!;


                    return datosUsuarioDto;
                }
                else
                {
                    datosUsuarioDto.EstaAutenticado = false;
                    datosUsuarioDto.Mensaje = $"Credenciales incorrectas para el usuario {usuario!.Username}.";

                    return datosUsuarioDto;
                }
            }

            datosUsuarioDto.EstaAutenticado = false;
            datosUsuarioDto.Mensaje = $"Credenciales incorrectas para el usuario {usuario.Username}.";

            return datosUsuarioDto;

        }

        private JwtSecurityToken CreateJwtToken(Usuario usuario)
        {
            if (usuario == null)
            {
                throw new ArgumentNullException(nameof(usuario), "El usuario no puede ser nulo.");
            }

            var roles = usuario.Roles;
            var roleClaims = new List<Claim>();
            foreach (var rol in roles!)
            {
                roleClaims.Add(new Claim("roles", rol.Nombre!));
            }

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, usuario.Username!),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim("uid", usuario.Id.ToString())
            }
            .Union(roleClaims);

            if (string.IsNullOrEmpty(_jwt.Key) || string.IsNullOrEmpty(_jwt.Issuer) || string.IsNullOrEmpty(_jwt.Audience))
            {
                throw new ArgumentNullException("La configuración del JWT es nula o vacía.");
            }

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));

            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256Signature);

            var JwtSecurityToken = new JwtSecurityToken(
                issuer: _jwt.Issuer,
                audience: _jwt.Audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(_jwt.DurationInMinutes),
                signingCredentials: signingCredentials);

            return JwtSecurityToken;
        }

    public Task<DataUserDto> RefreshTokenAsync(string refreshToken)
    {
        throw new NotImplementedException();
    }
}
























//  public async Task<string> RegisterAsync(RegisterDto registerDto)
//     {
//         var user = new User
//         {
//             Email = registerDto.Email,
//             Username = registerDto.Username
//         };

//         user.Password = _passwordHasher.HashPassword(user, registerDto.Password); //Encrypt password

//         var existingUser = _unitOfWork.Users
//                                     .Find(u => u.Username.ToLower() == registerDto.Username.ToLower())
//                                     .FirstOrDefault();

//         if (existingUser == null)
//         {
//             var rolDefault = _unitOfWork.Roles
//                                     .Find(u => u.Nombre == Authorization.rol_default.ToString())
//                                     .First();
//             try
//             {
//                 user.Rols.Add(rolDefault);
//                 _unitOfWork.Users.Add(user);
//                 await _unitOfWork.SaveAsync();

//                 return $"User  {registerDto.Username} has been registered successfully";
//             }
//             catch (Exception ex)
//             {
//                 var message = ex.Message;
//                 return $"Error: {message}";
//             }
//         }
//         else
//         {
//             return $"User {registerDto.Username} already registered.";
//         }
//     }
//     public async Task<DataUserDto> GetTokenAsync(LoginDto model)
//     {
//         DataUserDto dataUserDto = new DataUserDto();
//         var user = await _unitOfWork.Users
//                     .GetByUsernameAsync(model.Username);

//         if (user == null)
//         {
//             dataUserDto.IsAuthenticated = false;
//             dataUserDto.Message = $"User does not exist with username {model.Username}.";
//             return dataUserDto;
//         }

//         var result = _passwordHasher.VerifyHashedPassword(user, user.Password, model.Password);

//         if (result == PasswordVerificationResult.Success)
//         {
//             dataUserDto.IsAuthenticated = true;
//             JwtSecurityToken jwtSecurityToken = CreateJwtToken(user);
//             dataUserDto.Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
//             dataUserDto.Email = user.Email;
//             dataUserDto.UserName = user.Username;
//             dataUserDto.Roles = user.Rols
//                                             .Select(u => u.Nombre)
//                                             .ToList();

//             if (user.RefreshTokens.Any(a => a.IsActive))
//             {
//                 var activeRefreshToken = user.RefreshTokens.Where(a => a.IsActive == true).FirstOrDefault();
//                 dataUserDto.RefreshToken = activeRefreshToken.Token;
//                 dataUserDto.RefreshTokenExpiration = activeRefreshToken.Expires;
//             }
//             else
//             {
//                 var refreshToken = CreateRefreshToken();
//                 dataUserDto.RefreshToken = refreshToken.Token;
//                 dataUserDto.RefreshTokenExpiration = refreshToken.Expires;
//                 user.RefreshTokens.Add(refreshToken);
//                 _unitOfWork.Users.Update(user);
//                 await _unitOfWork.SaveAsync();
//             }

//             return dataUserDto;
//         }
//         dataUserDto.IsAuthenticated = false;
//         dataUserDto.Message = $"Credenciales incorrectas para el usuario {user.Username}.";
//         return dataUserDto;
//     }
//     public async Task<string> AddRoleAsync(AddRoleDto model)
//     {

//         var user = await _unitOfWork.Users
//                     .GetByUsernameAsync(model.Username);
//         if (user == null)
//         {
//             return $"User {model.Username} does not exists.";
//         }

//         var result = _passwordHasher.VerifyHashedPassword(user, user.Password, model.Password);

//         if (result == PasswordVerificationResult.Success)
//         {
//             var rolExists = _unitOfWork.Roles
//                                         .Find(u => u.Nombre.ToLower() == model.Role.ToLower())
//                                         .FirstOrDefault();

//             if (rolExists != null)
//             {
//                 var userHasRole = user.Rols
//                                             .Any(u => u.Id == rolExists.Id);

//                 if (userHasRole == false)
//                 {
//                     user.Rols.Add(rolExists);
//                     _unitOfWork.Users.Update(user);
//                     await _unitOfWork.SaveAsync();
//                 }

//                 return $"Role {model.Role} added to user {model.Username} successfully.";
//             }

//             return $"Role {model.Role} was not found.";
//         }
//         return $"Invalid Credentials";
//     }
//     public async Task<DataUserDto> RefreshTokenAsync(string refreshToken)
//     {
//         var dataUserDto = new DataUserDto();

//         var usuario = await _unitOfWork.Users
//                         .GetByRefreshTokenAsync(refreshToken);

//         if (usuario == null)
//         {
//             dataUserDto.IsAuthenticated = false;
//             dataUserDto.Message = $"Token is not assigned to any user.";
//             return dataUserDto;
//         }

//         var refreshTokenBd = usuario.RefreshTokens.Single(x => x.Token == refreshToken);

//         if (!refreshTokenBd.IsActive)
//         {
//             dataUserDto.IsAuthenticated = false;
//             dataUserDto.Message = $"Token is not active.";
//             return dataUserDto;
//         }
//         //Revoque the current refresh token and
//         refreshTokenBd.Revoked = DateTime.UtcNow;
//         //generate a new refresh token and save it in the database
//         var newRefreshToken = CreateRefreshToken();
//         usuario.RefreshTokens.Add(newRefreshToken);
//         _unitOfWork.Users.Update(usuario);
//         await _unitOfWork.SaveAsync();
//         //Generate a new Json Web Token
//         dataUserDto.IsAuthenticated = true;
//         JwtSecurityToken jwtSecurityToken = CreateJwtToken(usuario);
//         dataUserDto.Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
//         dataUserDto.Email = usuario.Email;
//         dataUserDto.UserName = usuario.Username;
//         dataUserDto.Roles = usuario.Rols
//                                         .Select(u => u.Nombre)
//                                         .ToList();
//         dataUserDto.RefreshToken = newRefreshToken.Token;
//         dataUserDto.RefreshTokenExpiration = newRefreshToken.Expires;
//         return dataUserDto;
//     }
//     private RefreshToken CreateRefreshToken()
//     {
//         var randomNumber = new byte[32];
//         using (var generator = RandomNumberGenerator.Create())
//         {
//             generator.GetBytes(randomNumber);
//             return new RefreshToken
//             {
//                 Token = Convert.ToBase64String(randomNumber),
//                 Expires = DateTime.UtcNow.AddDays(10),
//                 Created = DateTime.UtcNow
//             };
//         }
//     }
//     private JwtSecurityToken CreateJwtToken(User usuario)
//     {
//         var roles = usuario.Rols;
//         var roleClaims = new List<Claim>();
//         foreach (var role in roles)
//         {
//             roleClaims.Add(new Claim("roles", role.Nombre));
//         }
//         var claims = new[]
//         {
//                                 new Claim(JwtRegisteredClaimNames.Sub, usuario.Username),
//                                 new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
//                                 new Claim(JwtRegisteredClaimNames.Email, usuario.Email),
//                                 new Claim("uid", usuario.Id.ToString())
//                         }
//         .Union(roleClaims);
//         var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));
//         var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);
//         var jwtSecurityToken = new JwtSecurityToken(
//             issuer: _jwt.Issuer,
//             audience: _jwt.Audience,
//             claims: claims,
//             expires: DateTime.UtcNow.AddMinutes(_jwt.DurationInMinutes),
//             signingCredentials: signingCredentials);
//         return jwtSecurityToken;
//     }
