using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ServerAppTest1;
public interface IAlertService
{
    Task ShowAlertAsync(string title, string message, string cancelButton);
}