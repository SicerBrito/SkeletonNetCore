using Dominio.Entities;
using Dominio.Interfaces;
using Microsoft.EntityFrameworkCore;
using Persistencia.Data;

namespace Aplicacion.Repository;
public class UsuarioRepository : GenericRepository<Usuario>, IUsuario
{

    private readonly SicerContext _Context;
    public UsuarioRepository(SicerContext context) : base(context)
    {
        _Context = context;
    }

    public async Task<Usuario> GetByUsernameAsync(string username)
    {
        return (await _Context.Set<Usuario>()
                            .Include(u => u.Roles)
                            .FirstOrDefaultAsync(u => u.Username!.ToLower()==username.ToLower()))!;
    }
}
