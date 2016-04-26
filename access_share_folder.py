# -*- coding: utf-8 -*-
import win32security
import ntsecuritycon as con
import os
import wmi
import sys
import logging
import shutil
import glob

#настройки логгера
logging.basicConfig(format = u'%(levelname)-8s [%(asctime)s] %(message)s', level = logging.INFO , filename = u'C:\\scripts\\access_folder.log')

#Скипт для установки прав на папки , всё делается средствами NTFS прав 
#Для каждой папки берется список вложенных файлов и папок и устанавливаются права указанные в файле , присылаемомо из Lotus Notes в тектсовом файле
#Это мой первый скрипт на Python, так что тут оч много говнокода =( Прошу заранее простить и помиловать
#возможно позже переделаю чтобы права раздавать не через WINAPI к которому душа у меня не лежит , А через утилиту icacls или cacls

#получаем список расшаренных папок и проверяем, есть ли среди них наша
def PathSharedDirectory(folderName, ipServer):
	#Смотрим shared folder и их пути
	#подключаемся к пространству имен WMI
	c = wmi.WMI(ipServer)
	for share in c.Win32_Share():
		print (share.Caption)
		if share.Caption == folderName:
			folderPath = share.Path
			return folderPath
	logging.error('Ошибка! Сетевая папка %s не найдена!', folderName)
	return 1

#показывает список прав доступа к файлу\папке
def ShowAce(dacl):
	#возвращает количество прав доступа (пользователей или групп которым разрешен\запрещен доступ к файлу или папке)
	ace_count = dacl.GetAceCount()
    
	for i in range(0, ace_count):
		rev, access, usersid = dacl.GetAce(i)
		user, group, type  = win32security.LookupAccountSid('', usersid)
		print('User: {}/{}'.format(group, user), rev, access)
	print('\n')

#устанавливаем права для файло или папки 
def SetAcl(path, username, mask, rule):
	#получаем SID юзера, домен и тип , передаем в функцию имя системы , если параметр нулевый
	#то берем локальную систему, и имя пользователя или группы
	userx, domain, type = win32security.LookupAccountName ("", username)
	#флаг для включения наследования прав для вложенных файлов и папок 
	flags = win32security.OBJECT_INHERIT_ACE| win32security.CONTAINER_INHERIT_ACE
	#получаем длину дескриптор безопасности (SECURITY_DESCRIPTOR), передаем адрес каталога и
	#список DACL 
	sd = win32security.GetFileSecurity(path, win32security.DACL_SECURITY_INFORMATION)
	#
	dacl = sd.GetSecurityDescriptorDacl() # instead of dacl = win32security.ACL()
	if rule == 'del':
		#закрываем доступ к папке 
		dacl.AddAccessDeniedAceEx(win32security.ACL_REVISION_DS, flags, mask, userx)
	else:
 		#устанавливает NTFS права для папки и вложенных файлов, но не меняет у существующих
		dacl.AddAccessAllowedAceEx(win32security.ACL_REVISION_DS, flags, mask, userx)

	sd.SetSecurityDescriptorDacl(1, dacl, 0) 
	
	win32security.SetFileSecurity(path, win32security.DACL_SECURITY_INFORMATION, sd)
	#СДЕЛАТЬ ПРОВЕРКУ ЕСЛИ НЕ УДАЛОСЬ УСТАНОВИТЬ
	#ShowAce(dacl)
	logging.debug('%s Права установлены!', path)
	#print (path, "SET NEW ACL OK!")

#парсим файл, вытаскиваем оттуда имя пользователя, путь к папке, маску доступа, и действие (добавить пользователя или удалить)
def ParseFile (lotusExchangeFile):
	f = open(lotusExchangeFile, 'r')
	data = f.readline()
	#убираем перенос строки(на всякий)
	data = data.rstrip()
	f.close
	#parsePath = []
	#получаем из строки необходимые нам данные и пишем каждый в отдельную переменную
	action, username, security, networkPath = data.split('#')
	#парсим сетевой путь 
	parsePath = networkPath.split('\\')
	#исправить эти 4 строчки говнокода, пока что-то умнее не придумал, убираю каждый элемент списка который получили методом split выше
	#первый будет данные которые идут до 
	parsePath.pop(0)
	parsePath.pop(0)
	ipServer = parsePath.pop(0)
	folderName = parsePath.pop(0)

	fullPath = '\\'.join(parsePath)
	#print ("IP = ",ipServer, action, username, security,"full Path = ", fullPath, "Folder Name = ", folderName)	
	
	return action, username, security, folderName, ipServer, fullPath

#передаем сюда параметр полученный из файла для получения цифрового кода для установки прав доступа (6 основных прав)
def DecodeMask(security):
	typical_aces={
    "all":2032127,
    "re":1179817,
    "f":1180086,
    "r":1180095,
    "ch":1245631
	}
	
	mask = typical_aces.pop(security)
	#if (security == ) если маска не найдена сделать проверку
	return mask

#получаем список всех файлов вложенных в директорию 
def ChangeAcl(folderPath,username,mask,rule):
	filesList = [] #список вложенных файлов(пути к ним)
	foldersList = [folderPath] #список вложенных папок (пути к ним) включая путь к корневой
	SetAcl(folderPath,username,mask,rule)
	for file in os.listdir(folderPath):
		path = os.path.join(folderPath, file) # получаем полное имя
		if os.path.isfile(path):
			filesList.append(path)
			SetAcl(path,username,mask,rule)
		else:
			foldersList.append(path)
			SetAcl(path,username,mask,rule)
			filesList+=ChangeAcl(path,username,mask,rule)
	return filesList
	
def main(argv):
	logging.info(u'###########START#########')
	#Папка куда Lotus Notes выгружает файлы с данными
	lotusExchangeDir = '\\\\172.20.20.131\\Exchange\\itroles'
	#расширение выгружаемых файлов
	lotusExchangeTypeFile = '*.txt'
	#получаем полный путь к файлу с данными, если получаем пустой массив - то значит файла нет, и вызываем исключение
	try:
		lotusExchangeFile = glob.glob(lotusExchangeDir+'\\'+lotusExchangeTypeFile).pop(0)
	except IndexError:
		logging.info(u'Файл отсутствует!')
		logging.info(u'############END##########')
		return 0
	#парсим файл и получаем следуюище параметры action - действие над папкой(add, del) добавить права или удалить
	#username - имя доменной учетки
	#folderName - имя расшаренной папки на сервере, как оно выглядит в сети (прим. \\newserver\it  - имя папки будет it)
	#security - права доступа какие надо выставить (полные, чтение, запись и т.д.)
	#ipServer - айпи адрес или доменное имя сервера на котором находятся расщаренные папки
	#fullPath - путь к папке относительно расшаренной папки
	action, username, security, folderName, ipServer, fullPath = ParseFile(lotusExchangeFile)
	logging.info(u'Полученные данные. Имя пользователя: %s Действие: %s Права: %s Имя расшаренной папки: %s Адрес сервера: %s',username, action, security, folderName, ipServer )
	#проверяем существование расшаренной папки, и получаем её адрес на сервере в виде K:\PATH_FOLDER
	folderPath = PathSharedDirectory(folderName, ipServer)
	if ( folderPath == 1 ):
		return 1
	#получаем полный локальный путь к папке которую передали из Lotus Notes, так как путь до расшаренной папки может быть достаточно большим
	folderPath+='\\'
	folderPath+=fullPath
	logging.info(u'Локальный путь к папке: %s',folderPath)
	#доступ нет смысла закрывать к каждой папке и файлу, достаточно закрыть только к указанной и всё
	#так же необходимо именно запретить доступ, так как пользователь может находиться в группах, и тогда доступ останется
	if action == "del":
		mask = DecodeMask('all')
		SetAcl(folderPath,username,mask,action)
	else:
		mask = DecodeMask(security)
		ChangeAcl(folderPath,username,mask,security)
	#дописать проверку корректной установки прав и только потом удалить файл
	#после выполнения удаляем файл 
	#os.remove(lotusExchangeFile)
	# а пока в рамках тестирования перемещаем просто в другую папку
	wasteFolder = lotusExchangeDir + '\\waste_files\\'
	#shutil.move(lotusExchangeFile, wasteFolder)
	logging.info(u'############END##########')
	return 0
	
if __name__ == '__main__':
    sys.exit(main(sys.argv))