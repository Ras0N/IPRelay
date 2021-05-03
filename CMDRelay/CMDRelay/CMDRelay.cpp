// CMDRelay.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <Windows.h>
#include <windivert.h>
#pragma comment (lib,"WinDivert.lib")
static bool threadQuit = false;
//static UCHAR MTU = 1500;
static UINT32 orgIP = 0;
static UINT32 dstIP = 0;
DWORD WINAPI DoPackageInjecting(LPVOID p);
int main(int argc,char* argv[])
{
	if (argc < 3) {
		std::cout << "Wrong parameters!\n";
		std::cout << "usage: CMDRelay OriginalIP DestinationIP\n";
		return -1;
	}
	//UINT32 orgIP = 0;
	//UINT32 dstIP = 0;
	if (!WinDivertHelperParseIPv4Address(argv[1], &orgIP)) {
		std::cout << "Error while parsing OriginalIP!\n" << GetLastError() << std::endl;
		return -1;
	}
	orgIP = WinDivertHelperHtonl(orgIP);
	if (!WinDivertHelperParseIPv4Address(argv[2], &dstIP)) {
		std::cout << "Error while parsing DestinationIP!\n" << GetLastError() << std::endl;
		return -1;
	}
	dstIP = WinDivertHelperHtonl(dstIP);
	char* filter = new char[256];
	int r = snprintf(filter, 256, "(outbound and ip.DstAddr == %s) or (inbound and ip.SrcAddr == %s)", argv[1], argv[2]);
	if (r < 0 || r > 256) {
		std::cout << "failed to create filter string!\n";
		return -1;
	}
	std::cout << "Starting WinDivert ..." << std::endl;
	HANDLE winDivertHandle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, 0);
	if (winDivertHandle == INVALID_HANDLE_VALUE) {
		std::cout<<("error while open windivert!\n");
		return -1;
	}
	threadQuit = false;
	HANDLE hThread = CreateThread(NULL, 0, DoPackageInjecting, &winDivertHandle, 0, NULL);
	if (hThread == NULL) {
		std::cout<<("Failed to Chreat Thread!")<< GetLastError()<<std::endl;
		return -1;
	}
	while (TRUE) {
		getchar();
		break;
	}
	threadQuit = true;
	DWORD res = WaitForSingleObject(hThread, 5000);
	if (res != WAIT_OBJECT_0) {
		ExitThread(0L);
	}
	CloseHandle(hThread);
	WinDivertClose(winDivertHandle);
	Sleep(500);
	return 0;	
}
DWORD WINAPI DoPackageInjecting(LPVOID p) {
	HANDLE winDivertHandle = *(PHANDLE)p;
	UCHAR packet[WINDIVERT_MTU_MAX] = { 0, };
	UINT recv_len = 0;
	WINDIVERT_ADDRESS addr;
	PWINDIVERT_IPHDR ip_header = NULL;
	PWINDIVERT_UDPHDR udp_header = NULL;
	PWINDIVERT_TCPHDR tcp_header = NULL;
	//DWORD len;
	while (!threadQuit)
	{
		if (!WinDivertRecv(winDivertHandle,packet,sizeof(packet),&recv_len,&addr)){
			continue;
		}
		else {
			WinDivertHelperParsePacket(packet,sizeof(packet),&ip_header,NULL,NULL,NULL,NULL,&tcp_header,&udp_header, NULL, NULL, NULL, NULL);
			if (ip_header != NULL) {
				//INJECT PACKAGE
				//relay src -> dst
				if (addr.Outbound) {
					std::cout << "redirect outbound Package!\n";
					ip_header->DstAddr = dstIP;
					WinDivertHelperCalcChecksums(packet, sizeof(packet), &addr, 0);
					if (!WinDivertSend(winDivertHandle, packet, sizeof(packet), NULL, &addr)) {
						std::cout << "[Warning] failed to inject send packet! " << GetLastError() << std::endl;
						continue;
					}
				}
				else {
					std::cout << "redirect inbound Package!\n";
					ip_header->SrcAddr = orgIP;
					WinDivertHelperCalcChecksums(packet, sizeof(packet), &addr, 0);
					if (!WinDivertSend(winDivertHandle, packet, sizeof(packet), NULL, &addr)) {
						std::cout << "[Warning] failed to inject receive packet! " << GetLastError() << std::endl;
						continue;
					}
				}
			}
		}
	}
	return 0L;
}
// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
