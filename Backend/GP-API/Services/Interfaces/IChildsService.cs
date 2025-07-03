using GP_API.Models;

namespace GP_API.Services.Interfaces
{
    public interface IChildsService
    {
        IEnumerable<Child> GetAllChildren();
        Child GetChildById(int id);
        List<Child> GetChildrenByParentId(string id);
        void AddChild(Child child);
        void UpdateChild(Child child);
        void DeleteChild(Child child);
        void SaveChanges();
    }
}
