using Dominio.Entities;

namespace Dominio.Interfaces;
    public interface IUsuario : IGenericRepository<Usuario>{
    Task Find();
    Task FindByTypeIdCapitalizeId(string id);
    Task<Usuario> GetByUsernameAsync(string username);
        
    }
