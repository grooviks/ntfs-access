# ntfs-access
Set NTFS permissions on Windows share folder 
Из системы IBM Lotus выгружается файл txt в котором содержится информация об изменении прав доступа к общей папке,формат изменения следующий: 

action#domain_user_name#security#folder_path

action -либо add либо del   т.е. либо добавляем доступ либо удаляем

domain_user_name  доменное имя пользователя ,оно храниться в бд сотрудники в карточке пользователя

permission  all - Полный доступ  w- Изменение  r- Чтение

security   
        all - Полный доступ  
        ch - Изменение
        re - Чтение и выполнение
        f - Список содержимого папки
        r - Чтение
        w - Запись

folder_path  -путь к общей папке
